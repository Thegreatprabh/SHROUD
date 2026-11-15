"use strict";
/* SHROUD JavaScript protector (v1).
 *
 * Parses the input with esprima, applies AST transforms, emits with
 * escodegen, and prepends the runtime template (shroud/js/runtime.js).
 *
 * Usage:
 *   node protect.js --input <file> --output <file> --options <json file>
 *
 * Options (all optional): rename, string_encryption, flatten,
 * literal_encoding, dead_code, anti_debug, integrity, domain_lock (array),
 * seed (int|null), key (hex string, per-build XOR key; required when
 * string_encryption is on).
 *
 * Honest limits (also noted where they apply below):
 * - Protection raises the cost of reversal; it does not make it impossible.
 *   The string key and table ship inside the output.
 * - Template literals are left unencrypted.
 * - Control-flow flattening only applies to functions whose top-level
 *   statements contain no `let`/`const`, no nested function declarations,
 *   no try/switch/labels, and whose returns sit only at the top level or
 *   inside if/else branches (switch cases share one scope, and a `break`
 *   rewritten for a return must target the switch).
 * - Renaming is conservative: a name is renamed only if it is declared
 *   exactly once inside a single function tree and never collides with a
 *   global or another renamed name.
 */
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const esprima = require("esprima");
const escodegen = require("escodegen");

/* ------------------------------------------------------------------ */
/* CLI                                                                 */
/* ------------------------------------------------------------------ */
function parseArgs(argv) {
  const out = {};
  for (let i = 0; i < argv.length; i++) {
    if (argv[i].startsWith("--")) {
      out[argv[i].slice(2)] = argv[i + 1];
      i++;
    }
  }
  return out;
}

function main() {
  const args = parseArgs(process.argv.slice(2));
  if (!args.input || !args.output || !args.options) {
    console.error("usage: node protect.js --input <file> --output <file> --options <json file>");
    process.exit(2);
  }
  let options;
  try {
    options = JSON.parse(fs.readFileSync(args.options, "utf8"));
  } catch (e) {
    console.error("SHROUD: cannot read options file: " + e.message);
    process.exit(2);
  }
  const source = fs.readFileSync(args.input, "utf8");
  let ast;
  try {
    ast = esprima.parseScript(source, { tolerant: true });
  } catch (e) {
    try {
      ast = esprima.parseModule(source, { tolerant: true });
    } catch (e2) {
      console.error("SHROUD: parse error: " + (e2.message || e2));
      process.exit(1);
    }
  }
  try {
    const out = protect(ast, options);
    fs.writeFileSync(args.output, out, "utf8");
  } catch (e) {
    console.error("SHROUD: " + (e && e.stack ? e.stack : e));
    process.exit(1);
  }
}

/* ------------------------------------------------------------------ */
/* Generic AST helpers                                                 */
/* ------------------------------------------------------------------ */
function isNode(v) {
  return v !== null && typeof v === "object" && typeof v.type === "string";
}

/* Visit every node; `fn(node, parent, key)` may return a replacement node
 * (or `undefined` to keep the node). Children are visited after `fn`
 * runs on the parent (pre-order); replacements are spliced in. */
function traverse(node, parent, key, fn) {
  if (!isNode(node)) return node;
  const repl = fn(node, parent, key);
  if (repl !== undefined && repl !== node) node = repl;
  if (!isNode(node)) return node;
  for (const k of Object.keys(node)) {
    if (k === "parent") continue;
    const v = node[k];
    if (Array.isArray(v)) {
      for (let i = 0; i < v.length; i++) {
        if (isNode(v[i])) v[i] = traverse(v[i], node, k, fn);
      }
    } else if (isNode(v)) {
      node[k] = traverse(v, node, k, fn);
    }
  }
  return node;
}

/* Like traverse, but `fn` runs post-order (children first). */
function traversePost(node, fn) {
  if (!isNode(node)) return node;
  for (const k of Object.keys(node)) {
    const v = node[k];
    if (Array.isArray(v)) {
      for (let i = 0; i < v.length; i++) {
        if (isNode(v[i])) v[i] = traversePost(v[i], fn);
      }
    } else if (isNode(v)) {
      node[k] = traversePost(v, fn);
    }
  }
  const repl = fn(node);
  return repl === undefined ? node : repl;
}

function id(name) {
  return { type: "Identifier", name };
}
function lit(value) {
  return { type: "Literal", value };
}
function exprStmt(expr) {
  return { type: "ExpressionStatement", expression: expr };
}
function blockStmt(body) {
  return { type: "BlockStatement", body };
}

/* ------------------------------------------------------------------ */
/* Renaming                                                            */
/* ------------------------------------------------------------------ */
const GLOBALS = new Set([
  "window", "document", "console", "Math", "JSON", "Object", "Array",
  "String", "Number", "Boolean", "Promise", "setTimeout", "setInterval",
  "setImmediate", "clearTimeout", "clearInterval", "clearImmediate",
  "require", "module", "exports", "process", "Buffer", "__dirname",
  "__filename", "parseInt", "parseFloat", "isNaN", "isFinite", "eval",
  "global", "globalThis", "navigator", "location", "fetch", "alert",
  "Symbol", "Map", "Set", "WeakMap", "WeakSet", "Date", "RegExp", "Error",
  "TypeError", "RangeError", "SyntaxError", "ReferenceError", "Intl",
  "Reflect", "Proxy", "Function", "BigInt", "Atomics", "SharedArrayBuffer",
  "DataView", "ArrayBuffer", "Uint8Array", "Uint16Array", "Uint32Array",
  "Int8Array", "Int16Array", "Int32Array", "Float32Array", "Float64Array",
  "TextDecoder", "TextEncoder", "URL", "URLSearchParams", "atob", "btoa",
  "undefined", "NaN", "Infinity", "arguments", "this", "self", "top",
  "postMessage", "addEventListener", "removeEventListener",
  "_shroud_dec", "_shroud_state", "__ret",
]);

function isReserved(name) {
  return GLOBALS.has(name) || name.startsWith("_shroud");
}

/* Collect identifier names bound by a pattern (Identifier, ObjectPattern,
 * ArrayPattern, AssignmentPattern, RestElement). */
function collectPatternNames(pattern, out) {
  if (!isNode(pattern)) return;
  if (pattern.type === "Identifier") {
    out.push(pattern);
  } else if (pattern.type === "ObjectPattern") {
    for (const p of pattern.properties) {
      if (p.type === "Property") collectPatternNames(p.value, out);
      else collectPatternNames(p.argument, out);
    }
  } else if (pattern.type === "ArrayPattern") {
    for (const el of pattern.elements) {
      if (el) collectPatternNames(el, out);
    }
  } else if (pattern.type === "AssignmentPattern") {
    collectPatternNames(pattern.left, out);
  } else if (pattern.type === "RestElement") {
    collectPatternNames(pattern.argument, out);
  }
}

/* Scope object: { parent, func, root, declared: Map<name, {node, kind}>,
 * children: [] }. `root` is the nearest function/program scope id; `func`
 * is the nearest function/program scope object (var declarations and
 * function declarations bind there, not in the enclosing block). */
let scopeSeq = 0;
function newScope(parent, root) {
  const s = {
    id: scopeSeq++,
    parent,
    func: parent ? parent.func : null,
    root,
    declared: new Map(),
    children: [],
  };
  if (parent) parent.children.push(s);
  else s.func = s;
  return s;
}

function declareIn(scope, name, node, kind) {
  if (!scope.declared.has(name)) {
    scope.declared.set(name, { node, kind });
  }
}

/* Build the scope tree and record every identifier occurrence with its
 * role. Returns { scopes, occurrences } where each occurrence is
 * { node, role: "decl"|"ref"|"prop", scope }. */
function analyzeScopes(ast) {
  const scopes = [];
  const occurrences = [];
  const programScope = newScope(null, "program");
  scopes.push(programScope);

  function isLexicalDecl(node) {
    return node.type === "VariableDeclaration" && (node.kind === "let" || node.kind === "const");
  }

  function walk(node, scope, rootId) {
    if (!isNode(node)) return;
    // A bare Identifier reached directly (e.g. `var {...} = obj`, a
    // parameter default, a for-test) is a reference. Identifiers met as
    // children are classified by walkChildren instead, so this case only
    // fires for expression positions.
    if (node.type === "Identifier") {
      occurrences.push({ node, role: "ref", scope });
      return;
    }
    switch (node.type) {
      case "Program": {
        for (const st of node.body) walk(st, scope, rootId);
        return;
      }
      case "FunctionDeclaration":
      case "FunctionExpression":
      case "ArrowFunctionExpression": {
        const fnScope = newScope(scope, "fn" + scopeSeq);
        fnScope.func = fnScope;
        scopes.push(fnScope);
        // The function's own name: for declarations it binds in the
        // enclosing function scope; for named function expressions it is
        // visible only inside the function itself.
        if (node.id) {
          const declScope =
            node.type === "FunctionDeclaration" ? scope.func : fnScope;
          occurrences.push({ node: node.id, role: "decl", scope: declScope });
          declareIn(declScope, node.id.name, node.id, "function");
        }
        for (const p of node.params) {
          for (const n of collectNames(p)) {
            occurrences.push({ node: n, role: "decl", scope: fnScope });
            declareIn(fnScope, n.name, n, "param");
          }
          // References inside parameter default values (e.g. `f(a = dflt)`)
          // must be recorded, or renaming `dflt` would break them.
          walk(p, fnScope, fnScope.id);
        }
        walk(node.body, fnScope, fnScope.id);
        return;
      }
      case "BlockStatement": {
        const blockScope = newScope(scope, rootId);
        scopes.push(blockScope);
        for (const st of node.body) walk(st, blockScope, rootId);
        return;
      }
      case "SwitchStatement": {
        const swScope = newScope(scope, rootId);
        scopes.push(swScope);
        walk(node.discriminant, scope, rootId);
        for (const c of node.cases) {
          if (c.test) walk(c.test, scope, rootId);
          for (const st of c.consequent) walk(st, swScope, rootId);
        }
        return;
      }
      case "ForStatement":
      case "ForInStatement":
      case "ForOfStatement": {
        const forScope = newScope(scope, rootId);
        scopes.push(forScope);
        // The init/test/update/body all see the for-scope bindings.
        if (node.init) walk(node.init, forScope, rootId);
        if (node.test) walk(node.test, forScope, rootId);
        if (node.update) walk(node.update, forScope, rootId);
        if (node.left) walk(node.left, forScope, rootId);
        if (node.right) walk(node.right, forScope, rootId);
        walk(node.body, forScope, rootId);
        return;
      }
      case "CatchClause": {
        const catchScope = newScope(scope, rootId);
        scopes.push(catchScope);
        if (node.param) {
          for (const n of collectNames(node.param)) {
            occurrences.push({ node: n, role: "decl", scope: catchScope });
            declareIn(catchScope, n.name, n, "catch");
          }
          walk(node.param, catchScope, rootId);
        }
        walk(node.body, catchScope, rootId);
        return;
      }
      case "VariableDeclaration": {
        // `var` binds in the nearest function scope even when written
        // inside a block; `let`/`const` bind in the current block scope.
        const target = node.kind === "var" ? scope.func : scope;
        for (const d of node.declarations) {
          for (const n of collectNames(d.id)) {
            occurrences.push({ node: n, role: "decl", scope: target });
            declareIn(target, n.name, n, node.kind);
          }
          // References inside destructuring defaults (e.g. `{a = b}`).
          walk(d.id, scope, rootId);
          if (d.init) walk(d.init, scope, rootId);
        }
        return;
      }
      case "ClassDeclaration":
      case "ClassExpression": {
        if (node.id) {
          occurrences.push({ node: node.id, role: "decl", scope });
          declareIn(scope, node.id.name, node.id, "class");
        }
        walkChildren(node, scope, rootId);
        return;
      }
      case "ImportDeclaration":
      case "ExportNamedDeclaration":
      case "ExportAllDeclaration":
      case "ExportDefaultDeclaration": {
        // Imported/exported bindings are never renamed: treat their names
        // as program-scope declarations so references resolve to them.
        walkChildren(node, scope, rootId, /*markImports*/ true);
        return;
      }
      default: {
        walkChildren(node, scope, rootId);
        return;
      }
    }
  }

  function collectNames(pattern) {
    const out = [];
    collectPatternNames(pattern, out);
    return out;
  }

  function walkChildren(node, scope, rootId, markImports) {
    for (const k of Object.keys(node)) {
      const v = node[k];
      const handle = (child, parentKey) => {
        if (!isNode(child)) return;
        if (child.type === "Identifier") {
          const role = classifyIdentifier(node, parentKey, child);
          if (role === "ref" && markImports) {
            // Import/export specifier binding: record as a program decl.
            occurrences.push({ node: child, role: "decl", scope: programScope });
            declareIn(programScope, child.name, child, "import");
          } else {
            occurrences.push({ node: child, role, scope });
          }
          return;
        }
        walk(child, scope, rootId);
      };
      if (Array.isArray(v)) {
        for (const c of v) handle(c, k);
      } else {
        handle(v, k);
      }
    }
  }

  /* Decide whether an Identifier child of `parent` (under key `key`) is a
   * declaration, a property name, or a variable reference. */
  function classifyIdentifier(parent, key, child) {
    switch (parent.type) {
      case "MemberExpression":
        if (key === "property" && !parent.computed) return "prop";
        return "ref";
      case "Property":
      case "PropertyDefinition":
        if (key === "key" && !parent.computed) return "prop";
        return "ref";
      case "MethodDefinition":
        if (key === "key" && !parent.computed) return "prop";
        return "ref";
      case "LabeledStatement":
      case "BreakStatement":
      case "ContinueStatement":
        if (key === "label") return "prop";
        return "ref";
      case "ImportSpecifier":
      case "ImportDefaultSpecifier":
      case "ImportNamespaceSpecifier":
      case "ExportSpecifier":
        return "prop";
      default:
        return "ref";
    }
  }

  walk(ast, programScope, "program");
  return { scopes, occurrences, programScope };
}

/* Resolve a reference: innermost scope (starting at `scope`) that declares
 * `name`, or null for globals/free variables. */
function resolveScope(scope, name) {
  let s = scope;
  while (s) {
    if (s.declared.has(name)) return s;
    s = s.parent;
  }
  return null;
}

function renameIdentifiers(ast, seed) {
  const { occurrences, programScope } = analyzeScopes(ast);

  // Group scopes by their function root (program root = "program").
  const roots = new Map(); // rootId -> { declCount: Map<name, count>, scopes: [] }
  function rootOf(scope) {
    return scope.root;
  }
  // Count, per root, how many scopes declare each name.
  const perRoot = new Map();
  const allScopes = [];
  (function collect(scope) {
    allScopes.push(scope);
    for (const c of scope.children) collect(c);
  })(programScope);
  for (const s of allScopes) {
    const r = rootOf(s);
    if (!perRoot.has(r)) perRoot.set(r, new Map());
    const m = perRoot.get(r);
    for (const name of s.declared.keys()) {
      m.set(name, (m.get(name) || 0) + 1);
    }
  }

  // Deterministic counter; the seed shifts the start so different seeds
  // produce different names (the key also differs per seed).
  let counter = 1;
  if (seed !== null && seed !== undefined) {
    counter = ((Math.imul(seed | 0, 2654435761) >>> 0) % 0x1000) + 1;
  }
  const taken = new Set(GLOBALS);
  for (const s of allScopes) {
    for (const name of s.declared.keys()) taken.add(name);
  }
  function freshName() {
    let n;
    do {
      n = "_0x" + (counter++).toString(16);
    } while (taken.has(n));
    taken.add(n);
    return n;
  }

  // Rename map: scope object -> Map<oldName, newName>.
  const renameMap = new Map();
  for (const s of allScopes) {
    if (s.root === "program") continue; // never rename program-scope names
    const counts = perRoot.get(s.root);
    const map = new Map();
    for (const [name] of s.declared) {
      if (isReserved(name)) continue;
      if (counts.get(name) !== 1) continue; // shadowed somewhere in this function tree
      map.set(name, freshName());
    }
    if (map.size) renameMap.set(s, map);
  }
  if (!renameMap.size) return;

  // Apply: for every decl/ref occurrence, resolve its declaration scope and
  // rewrite the identifier if that scope renamed the name.
  for (const occ of occurrences) {
    if (occ.role === "prop") continue;
    const declScope = resolveScope(occ.scope, occ.node.name);
    if (!declScope) continue;
    const map = renameMap.get(declScope);
    if (map && map.has(occ.node.name)) {
      occ.node.name = map.get(occ.node.name);
    }
  }

  // Shorthand properties (`{a}`) print only the key: if the value was
  // renamed, the property is no longer shorthand and must print as
  // `{a: _0x..}`, or the renamed binding would be silently dropped.
  traverse(ast, null, null, (node) => {
    if (
      node.type === "Property" &&
      node.shorthand &&
      node.key &&
      node.value &&
      node.key.name !== node.value.name
    ) {
      node.shorthand = false;
    }
    return undefined;
  });
}

/* ------------------------------------------------------------------ */
/* String encryption                                                   */
/* ------------------------------------------------------------------ */
function encryptStrings(ast, keyBytes, table) {
  const tableIndex = new Map();
  const skip = new Set(); // Literal nodes that are directive prologues

  // Mark directive prologues (program + each function body).
  function markDirectives(body) {
    for (const st of body) {
      if (
        st.type === "ExpressionStatement" &&
        st.expression.type === "Literal" &&
        typeof st.expression.value === "string"
      ) {
        skip.add(st.expression);
      } else {
        break;
      }
    }
  }
  markDirectives(ast.body);
  traverse(ast, null, null, (node) => {
    if (
      (node.type === "FunctionDeclaration" ||
        node.type === "FunctionExpression" ||
        node.type === "ArrowFunctionExpression") &&
      node.body &&
      node.body.type === "BlockStatement"
    ) {
      markDirectives(node.body.body);
    }
    return undefined;
  });

  function encrypt(str) {
    if (!tableIndex.has(str)) {
      const bytes = Buffer.from(str, "utf8");
      const enc = Buffer.alloc(bytes.length);
      for (let i = 0; i < bytes.length; i++) {
        enc[i] = bytes[i] ^ keyBytes[i % keyBytes.length];
      }
      tableIndex.set(str, table.length);
      table.push(enc.toString("base64"));
    }
    return tableIndex.get(str);
  }

  // Walk with a "skip strings here" flag for import/export statements
  // (module specifiers must stay literal) and for object property keys.
  (function walkStrings(node, parent, key, skipStrings) {
    if (!isNode(node)) return node;
    if (
      node.type === "ImportDeclaration" ||
      node.type === "ExportNamedDeclaration" ||
      node.type === "ExportAllDeclaration" ||
      node.type === "ImportExpression"
    ) {
      skipStrings = true;
    }
    if (
      node.type === "Literal" &&
      typeof node.value === "string" &&
      !skip.has(node) &&
      !skipStrings
    ) {
      // Object property keys (non-computed) stay literal: the key is a
      // Literal whose parent is a Property/MethodDefinition with
      // computed === false.
      const isPropKey =
        parent &&
        (parent.type === "Property" ||
          parent.type === "MethodDefinition" ||
          parent.type === "PropertyDefinition") &&
        key === "key" &&
        !parent.computed;
      if (!isPropKey) {
        const idx = encrypt(node.value);
        return {
          type: "CallExpression",
          callee: id("_shroud_dec"),
          arguments: [lit(idx)],
        };
      }
      return node;
    }
    for (const k of Object.keys(node)) {
      const v = node[k];
      if (Array.isArray(v)) {
        for (let i = 0; i < v.length; i++) {
          if (isNode(v[i])) v[i] = walkStrings(v[i], node, k, skipStrings);
        }
      } else if (isNode(v)) {
        node[k] = walkStrings(v, node, k, skipStrings);
      }
    }
    return node;
  })(ast, null, null, false);
}

/* ------------------------------------------------------------------ */
/* Numeric encoding                                                    */
/* ------------------------------------------------------------------ */
function encodeNumbers(ast) {
  function encode(n) {
    // 0 and 1 stay literal (short and unambiguous); anything else becomes
    // a small hex + decimal addition evaluating to the same value.
    if (n < 2 || !Number.isInteger(n)) return null;
    const hi = Math.floor(n / 2);
    return {
      type: "BinaryExpression",
      operator: "+",
      left: { type: "Literal", value: hi, raw: "0x" + hi.toString(16) },
      right: lit(n - hi),
    };
  }
  (function walk(node, parent, key) {
    if (!isNode(node)) return node;
    if (node.type === "Literal" && typeof node.value === "number") {
      const skipParent =
        parent &&
        ((parent.type === "Property" ||
          parent.type === "MethodDefinition" ||
          parent.type === "PropertyDefinition") &&
          key === "key" &&
          !parent.computed);
      const skipCase = parent && parent.type === "SwitchCase" && key === "test";
      if (!skipParent && !skipCase) {
        const enc = encode(node.value);
        if (enc) return enc;
      }
      return node;
    }
    for (const k of Object.keys(node)) {
      const v = node[k];
      if (Array.isArray(v)) {
        for (let i = 0; i < v.length; i++) {
          if (isNode(v[i])) v[i] = walk(v[i], node, k);
        }
      } else if (isNode(v)) {
        node[k] = walk(v, node, k);
      }
    }
    return node;
  })(ast, null, null);
}

/* ------------------------------------------------------------------ */
/* Control-flow flattening                                             */
/* ------------------------------------------------------------------ */
function isDirective(stmt) {
  return (
    stmt.type === "ExpressionStatement" &&
    stmt.expression.type === "Literal" &&
    typeof stmt.expression.value === "string"
  );
}

/* Does the subtree contain a node of one of the given types, without
 * descending into nested functions? */
function subtreeHas(node, types) {
  let found = false;
  (function walk(n) {
    if (!isNode(n) || found) return;
    if (types.has(n.type)) {
      found = true;
      return;
    }
    if (
      n.type === "FunctionDeclaration" ||
      n.type === "FunctionExpression" ||
      n.type === "ArrowFunctionExpression"
    ) {
      return; // nested function: its body belongs to it, not to us
    }
    for (const k of Object.keys(n)) {
      const v = n[k];
      if (Array.isArray(v)) for (const c of v) walk(c);
      else walk(v);
    }
  })(node);
  return found;
}

/* Collect return statements in `node` (not descending into nested
 * functions) together with their ancestor chain inside `node`. */
function collectReturns(node) {
  const out = [];
  (function walk(n, ancestors) {
    if (!isNode(n)) return;
    if (
      n.type === "FunctionDeclaration" ||
      n.type === "FunctionExpression" ||
      n.type === "ArrowFunctionExpression"
    ) {
      return;
    }
    if (n.type === "ReturnStatement") {
      out.push({ node: n, ancestors: [...ancestors] });
      return;
    }
    for (const k of Object.keys(n)) {
      const v = n[k];
      if (Array.isArray(v)) for (const c of v) walk(c, [...ancestors, n.type]);
      else walk(v, [...ancestors, n.type]);
    }
  })(node, []);
  return out;
}

const RETURN_BLOCKERS = new Set([
  "ForStatement", "ForInStatement", "ForOfStatement", "WhileStatement",
  "DoWhileStatement", "TryStatement", "SwitchStatement",
]);

function canFlatten(fnNode) {
  if (fnNode.generator || fnNode.async) return false;
  if (!fnNode.body || fnNode.body.type !== "BlockStatement") return false;
  const body = fnNode.body.body;
  let idx = 0;
  while (idx < body.length && isDirective(body[idx])) idx++;
  const stmts = body.slice(idx);
  if (stmts.length === 0) return false;
  // The state machine introduces these names; bail out on collision.
  const declared = new Set();
  for (const st of stmts) {
    if (st.type === "VariableDeclaration") {
      for (const d of st.declarations) {
        const names = [];
        collectPatternNames(d.id, names);
        for (const n of names) declared.add(n.name);
      }
    }
  }
  if (declared.has("_shroud_state") || declared.has("__ret")) return false;
  for (const st of stmts) {
    if (st.type === "VariableDeclaration" && (st.kind === "let" || st.kind === "const")) {
      return false; // switch cases share one scope
    }
    if (
      st.type === "FunctionDeclaration" ||
      st.type === "LabeledStatement" ||
      st.type === "TryStatement" ||
      st.type === "SwitchStatement" ||
      st.type === "WithStatement"
    ) {
      return false;
    }
    // No nested function declarations, try/switch/labels/with anywhere in
    // the statement (their bodies belong to this function for scoping).
    if (
      subtreeHas(st, new Set([
        "FunctionDeclaration", "TryStatement", "SwitchStatement",
        "LabeledStatement", "WithStatement",
      ]))
    ) {
      return false;
    }
    // Returns may only sit at the top level or inside if/else branches.
    for (const r of collectReturns(st)) {
      for (const a of r.ancestors) {
        if (RETURN_BLOCKERS.has(a)) return false;
      }
    }
  }
  return true;
}

/* Rewrite ReturnStatement nodes inside `stmt` (not in nested functions)
 * into `{ __ret = <arg>; _shroud_state = -1; break; }` blocks. */
function rewriteReturns(stmt) {
  function map(n) {
    if (!isNode(n)) return n;
    if (n.type === "ReturnStatement") {
      return blockStmt([
        {
          type: "ExpressionStatement",
          expression: {
            type: "AssignmentExpression",
            operator: "=",
            left: id("__ret"),
            right: n.argument || { type: "Identifier", name: "undefined" },
          },
        },
        {
          type: "ExpressionStatement",
          expression: {
            type: "AssignmentExpression",
            operator: "=",
            left: id("_shroud_state"),
            right: { type: "UnaryExpression", operator: "-", argument: lit(1), prefix: true },
          },
        },
        { type: "BreakStatement" },
      ]);
    }
    if (
      n.type === "FunctionDeclaration" ||
      n.type === "FunctionExpression" ||
      n.type === "ArrowFunctionExpression"
    ) {
      return n;
    }
    for (const k of Object.keys(n)) {
      const v = n[k];
      if (Array.isArray(v)) {
        for (let i = 0; i < v.length; i++) {
          if (isNode(v[i])) v[i] = map(v[i]);
        }
      } else if (isNode(v)) {
        n[k] = map(v);
      }
    }
    return n;
  }
  return map(stmt);
}

function flattenFunction(fnNode) {
  if (!canFlatten(fnNode)) return false;
  const body = fnNode.body.body;
  let idx = 0;
  const directives = [];
  while (idx < body.length && isDirective(body[idx])) {
    directives.push(body[idx]);
    idx++;
  }
  const stmts = body.slice(idx);
  const n = stmts.length;
  const cases = stmts.map((stmt, i) => {
    const rewritten = rewriteReturns(stmt);
    const advance = {
      type: "IfStatement",
      test: {
        type: "BinaryExpression",
        operator: "!==",
        left: id("_shroud_state"),
        right: { type: "UnaryExpression", operator: "-", argument: lit(1), prefix: true },
      },
      consequent: blockStmt([
        exprStmt({
          type: "AssignmentExpression",
          operator: "=",
          left: id("_shroud_state"),
          right: lit(i + 1),
        }),
      ]),
      alternate: null,
    };
    return {
      type: "SwitchCase",
      test: lit(i),
      consequent: [rewritten, advance, { type: "BreakStatement" }],
    };
  });
  const loop = {
    type: "WhileStatement",
    test: lit(true),
    body: blockStmt([
      {
        type: "SwitchStatement",
        discriminant: id("_shroud_state"),
        cases,
      },
      {
        type: "IfStatement",
        test: {
          type: "LogicalExpression",
          operator: "||",
          left: {
            type: "BinaryExpression",
            operator: "===",
            left: id("_shroud_state"),
            right: { type: "UnaryExpression", operator: "-", argument: lit(1), prefix: true },
          },
          right: {
            type: "BinaryExpression",
            operator: ">=",
            left: id("_shroud_state"),
            right: lit(n),
          },
        },
        consequent: blockStmt([{ type: "BreakStatement" }]),
        alternate: null,
      },
    ]),
  };
  fnNode.body.body = [
    ...directives,
    {
      type: "VariableDeclaration",
      kind: "var",
      declarations: [
        { type: "VariableDeclarator", id: id("_shroud_state"), init: lit(0) },
        { type: "VariableDeclarator", id: id("__ret"), init: null },
      ],
    },
    loop,
    { type: "ReturnStatement", argument: id("__ret") },
  ];
  return true;
}

function flattenAll(ast) {
  traverse(ast, null, null, (node) => {
    if (
      node.type === "FunctionDeclaration" ||
      node.type === "FunctionExpression" ||
      node.type === "ArrowFunctionExpression"
    ) {
      flattenFunction(node);
    }
    return undefined;
  });
}

/* ------------------------------------------------------------------ */
/* Dead code                                                           */
/* ------------------------------------------------------------------ */
function injectDeadCode(ast, rngState) {
  // Deterministic junk numbers (seeded by the build counter, not by
  // Math.random, so seeded builds are reproducible).
  const a = 100 + ((rngState.next() * 900) | 0);
  const b = 100 + ((rngState.next() * 900) | 0);
  const c = 10 + ((rngState.next() * 90) | 0);
  const junkBlock = {
    type: "IfStatement",
    test: lit(false),
    consequent: blockStmt([
      {
        type: "VariableDeclaration",
        kind: "var",
        declarations: [
          {
            type: "VariableDeclarator",
            id: id("_shroud_junk0"),
            init: {
              type: "BinaryExpression",
              operator: "+",
              left: {
                type: "BinaryExpression",
                operator: "*",
                left: lit(a),
                right: lit(b),
              },
              right: lit(c),
            },
          },
        ],
      },
      exprStmt({
        type: "BinaryExpression",
        operator: "+",
        left: id("_shroud_junk0"),
        right: lit(1),
      }),
    ]),
    alternate: null,
  };
  const junkFn = {
    type: "FunctionDeclaration",
    id: id("_shroud_junk_fn"),
    params: [],
    body: blockStmt([{ type: "ReturnStatement", argument: lit(0) }]),
    generator: false,
    async: false,
    expression: false,
  };
  // Insert after any directive prologue so "use strict" keeps working.
  let at = 0;
  while (at < ast.body.length && isDirective(ast.body[at])) at++;
  ast.body.splice(at, 0, junkBlock, junkFn);
}

/* ------------------------------------------------------------------ */
/* Driver                                                              */
/* ------------------------------------------------------------------ */
function seededRng(seed) {
  // mulberry32; deterministic per seed.
  let s = (seed | 0) >>> 0;
  return {
    next() {
      s = (s + 0x6d2b79f5) | 0;
      let t = s;
      t = Math.imul(t ^ (t >>> 15), t | 1);
      t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
      return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
    },
  };
}

function protect(ast, options) {
  const seed = options.seed === undefined ? null : options.seed;
  const keyBytes = options.key
    ? Buffer.from(options.key, "hex")
    : crypto.randomBytes(16);
  if (keyBytes.length === 0) throw new Error("empty string-encryption key");
  const table = [];
  const rng = seed === null ? { next: () => Math.random() } : seededRng(seed);

  if (options.rename !== false) renameIdentifiers(ast, seed);
  if (options.flatten !== false) flattenAll(ast);
  if (options.literal_encoding !== false) encodeNumbers(ast);
  if (options.string_encryption !== false) encryptStrings(ast, keyBytes, table);
  if (options.dead_code !== false) injectDeadCode(ast, rng);

  let code = escodegen.generate(ast);

  // Runtime template with placeholder substitution.
  const runtimePath = path.join(__dirname, "..", "runtime.js");
  let runtime = fs.readFileSync(runtimePath, "utf8");
  const integrityHash =
    options.integrity === false
      ? ""
      : crypto.createHash("sha256").update(table.join("\n"), "utf8").digest("hex");
  runtime = runtime
    .split("__SHROUD_TABLE__").join(JSON.stringify(table))
    .split("__SHROUD_KEY__").join(JSON.stringify(Array.from(keyBytes)))
    .split("__SHROUD_INTEGRITY_HASH__").join(integrityHash)
    .split("__SHROUD_DOMAINS__").join(JSON.stringify(options.domain_lock || []))
    .split("__SHROUD_ANTI_DEBUG__").join(options.anti_debug === false ? "false" : "true");

  // Keep directive prologues ("use strict") ahead of the runtime so they
  // stay effective; the runtime itself is not a directive.
  let directives = "";
  const dirRe = /^(?:"(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*');\s*/;
  let rest = code;
  let m;
  while ((m = rest.match(dirRe))) {
    directives += m[0];
    rest = rest.slice(m[0].length);
  }
  return directives + runtime + "\n" + rest;
}

if (require.main === module) main();
