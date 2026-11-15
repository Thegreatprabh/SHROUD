"""AST transforms for the SHROUD Python engine.

Honest limit: these transforms raise the cost of reversing protected code;
they do not make reversal impossible. The decryption key lives in the
delivered runtime (``shroud_runtime.py``); a determined attacker with full
access to the delivered files can eventually extract it.

Every transform here is behaviour-preserving (or documented where a
construct is deliberately left alone) and toggleable via the options dict.
All transforms use stdlib ``ast`` only.
"""

from __future__ import annotations

import ast
import base64
import random
import re


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

def _is_dunder(name: str) -> bool:
    return name.startswith("__") and name.endswith("__") and len(name) > 4


def _collect_string_constants(node):
    """Yield every Constant(str) node under ``node``."""
    for child in ast.walk(node):
        if isinstance(child, ast.Constant) and isinstance(child.value, str):
            yield child


def _docstring_node(body):
    """Return the Constant node of a docstring if body starts with one."""
    if not body:
        return None
    first = body[0]
    if (
        isinstance(first, ast.Expr)
        and isinstance(first.value, ast.Constant)
        and isinstance(first.value.value, str)
    ):
        return first.value
    return None


def _skip_ids_for_strings(tree):
    """Ids of str constants that string encryption must NOT touch.

    Skipped: docstrings, f-strings (JoinedStr subtrees), strings inside
    annotations, and strings used as dict keys.
    """
    skip = set()

    for node in ast.walk(tree):
        # Docstrings.
        if isinstance(node, (ast.Module, ast.ClassDef, ast.FunctionDef,
                             ast.AsyncFunctionDef)):
            doc = _docstring_node(node.body)
            if doc is not None:
                skip.add(id(doc))
        # F-strings: leave the whole JoinedStr subtree alone.
        if isinstance(node, ast.JoinedStr):
            for const in _collect_string_constants(node):
                skip.add(id(const))
        # Dict keys.
        if isinstance(node, ast.Dict):
            for key in node.keys:
                if key is not None:
                    for const in _collect_string_constants(key):
                        skip.add(id(const))
        # Annotations: AnnAssign annotation, function/class annotations.
        if isinstance(node, ast.AnnAssign):
            for const in _collect_string_constants(node.annotation):
                skip.add(id(const))
        # Match patterns: a literal pattern must stay a literal — a
        # dec() call is not valid pattern syntax (it parses as a class
        # pattern and fails at runtime).
        if isinstance(node, ast.match_case):
            for const in _collect_string_constants(node.pattern):
                skip.add(id(const))
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            for arg in (
                list(node.args.posonlyargs) + list(node.args.args)
                + list(node.args.kwonlyargs)
            ):
                if arg.annotation is not None:
                    for const in _collect_string_constants(arg.annotation):
                        skip.add(id(const))
            if node.args.vararg is not None and node.args.vararg.annotation is not None:
                for const in _collect_string_constants(node.args.vararg.annotation):
                    skip.add(id(const))
            if node.args.kwarg is not None and node.args.kwarg.annotation is not None:
                for const in _collect_string_constants(node.args.kwarg.annotation):
                    skip.add(id(const))
            if node.returns is not None:
                for const in _collect_string_constants(node.returns):
                    skip.add(id(const))
        if isinstance(node, ast.arg) and node.annotation is not None:
            for const in _collect_string_constants(node.annotation):
                skip.add(id(const))

    return skip


def _skip_ids_for_ints(tree):
    """Ids of int constants that literal encoding must NOT touch.

    Skipped: dict keys and ints inside annotations.
    """
    skip = set()

    def _add_ints(node):
        for child in ast.walk(node):
            if isinstance(child, ast.Constant) and type(child.value) is int:
                skip.add(id(child))

    for node in ast.walk(tree):
        if isinstance(node, ast.Dict):
            for key in node.keys:
                if key is not None:
                    _add_ints(key)
        if isinstance(node, ast.AnnAssign):
            _add_ints(node.annotation)
        # Match patterns: an encoded int (e.g. `21 + 21`) is not valid
        # pattern syntax. Subject/guard expressions are NOT skipped.
        if isinstance(node, ast.match_case):
            _add_ints(node.pattern)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            for arg in (
                list(node.args.posonlyargs) + list(node.args.args)
                + list(node.args.kwonlyargs)
            ):
                if arg.annotation is not None:
                    _add_ints(arg.annotation)
            if node.returns is not None:
                _add_ints(node.returns)
    return skip


def _xor_bytes(data: bytes, key: bytes) -> bytes:
    if not key:
        return data
    return bytes(b ^ key[i % len(key)] for i, b in enumerate(data))


def encrypt_string(value: str, key: bytes) -> str:
    """XOR ``value`` with ``key`` (cycling) and base64-encode it."""
    raw = _xor_bytes(value.encode("utf-8"), key)
    return base64.b64encode(raw).decode("ascii")


def decrypt_string(encoded: str, key: bytes) -> str:
    raw = base64.b64decode(encoded.encode("ascii"))
    return _xor_bytes(raw, key).decode("utf-8")


def _make_dec_call(encoded: str) -> ast.Call:
    """Build ``shroud_runtime.dec("<base64>")``."""
    return ast.Call(
        func=ast.Attribute(
            value=ast.Name(id="shroud_runtime", ctx=ast.Load()),
            attr="dec",
            ctx=ast.Load(),
        ),
        args=[ast.Constant(value=encoded)],
        keywords=[],
    )


# ---------------------------------------------------------------------------
# Renaming (scope-aware)
# ---------------------------------------------------------------------------

# Conventional first parameters and names that must never be renamed.
_NEVER_RENAME = {"self", "cls"}

# Names bound by an import anywhere in the module are never renamed.
def _module_imported_names(tree):
    names = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                names.add((alias.asname or alias.name).split(".")[0])
        elif isinstance(node, ast.ImportFrom):
            for alias in node.names:
                names.add(alias.asname or alias.name)
    return names


def _names_assigned_direct(func):
    """Names assigned in ``func``'s own scope (not nested funcs/classes).

    Includes parameters, assignment targets, for/with targets, named
    expressions, except-handler names, and walrus targets. Comprehension
    targets are NOT function locals in Python 3 and are excluded.
    """
    assigned = set()

    def _add_target(target):
        if isinstance(target, ast.Name):
            assigned.add(target.id)
        elif isinstance(target, (ast.Tuple, ast.List)):
            for elt in target.elts:
                _add_target(elt)
        elif isinstance(target, ast.Starred):
            _add_target(target.value)

    def _visit(node):
        # Do not descend into nested functions/classes/lambdas: their
        # locals belong to them, not to this scope.
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef,
                             ast.ClassDef, ast.Lambda)) and node is not func:
            return
        if isinstance(node, ast.comprehension):
            # Comprehension target is its own scope; still visit its
            # iterator (evaluated in the enclosing scope).
            _visit(node.iter)
            for cond in node.ifs:
                _visit(cond)
            return
        if isinstance(node, ast.NamedExpr):
            _add_target(node.target)
        if isinstance(node, ast.Assign):
            for t in node.targets:
                _add_target(t)
        elif isinstance(node, ast.AnnAssign):
            _add_target(node.target)
        elif isinstance(node, ast.AugAssign):
            _add_target(node.target)
        elif isinstance(node, (ast.For, ast.AsyncFor)):
            _add_target(node.target)
        elif isinstance(node, ast.With):
            for item in node.items:
                if item.optional_vars is not None:
                    _add_target(item.optional_vars)
        elif isinstance(node, ast.AsyncWith):
            for item in node.items:
                if item.optional_vars is not None:
                    _add_target(item.optional_vars)
        elif isinstance(node, ast.ExceptHandler):
            if node.name:
                assigned.add(node.name)
        elif isinstance(node, ast.MatchAs):
            # Capture pattern: binds a name in the enclosing scope.
            if node.name:
                assigned.add(node.name)
        elif isinstance(node, ast.MatchStar):
            if node.name:
                assigned.add(node.name)
        elif isinstance(node, ast.MatchMapping):
            if node.rest:
                assigned.add(node.rest)
        for child in ast.iter_child_nodes(node):
            _visit(child)

    # Parameters.
    args = func.args
    for arg in (
        list(args.posonlyargs) + list(args.args) + list(args.kwonlyargs)
    ):
        assigned.add(arg.arg)
    if args.vararg is not None:
        assigned.add(args.vararg.arg)
    if args.kwarg is not None:
        assigned.add(args.kwarg.arg)

    for stmt in func.body:
        _visit(stmt)
    return assigned


def _all_name_ids_direct(func):
    """All Name ids used in ``func``'s own scope (not nested scopes)."""
    ids = set()

    def _visit(node):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef,
                             ast.ClassDef, ast.Lambda)) and node is not func:
            return
        if isinstance(node, ast.comprehension):
            _visit(node.iter)
            for cond in node.ifs:
                _visit(cond)
            return
        if isinstance(node, ast.Name):
            ids.add(node.id)
        for child in ast.iter_child_nodes(node):
            _visit(child)

    for stmt in func.body:
        _visit(stmt)
    # Defaults / decorators / annotations live in the enclosing scope.
    for node in (
        list(func.decorator_list) + list(func.args.defaults)
        + list(func.args.kw_defaults)
    ):
        if node is not None:
            for child in ast.walk(node):
                if isinstance(child, ast.Name):
                    ids.add(child.id)
    return ids


def _names_referenced_in_nested(func):
    """Names read/written inside nested functions/classes/lambdas.

    Those are free variables (closures) or nested locals; renaming the
    outer binding would break the closure read, so they are excluded.
    """
    refs = set()

    def _visit(node, inside_nested):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef,
                             ast.ClassDef, ast.Lambda)) and node is not func:
            inside_nested = True
        if inside_nested and isinstance(node, ast.Name):
            refs.add(node.id)
        for child in ast.iter_child_nodes(node):
            _visit(child, inside_nested)

    for stmt in func.body:
        _visit(stmt, False)
    return refs


class RenameTransformer(ast.NodeTransformer):
    """Rename local variables and function parameters, scope-aware.

    Never renames: module-level names, class names, attribute names,
    imported names, dunder names, ``self``/``cls``, names declared
    ``global``/``nonlocal``, names read by a nested scope (closures), or
    any name whose rename would collide with another name in scope.
    New names are ``_s`` + hex counter, offset by the seed when given.
    """

    def __init__(self, seed=None):
        super().__init__()
        self._seed = seed
        self._counter = 0
        self._offset = 0
        if seed is not None:
            self._offset = random.Random(seed).randrange(0, 0x1000)
        self._imported = set()
        # Stack of (mapping, comprehension-shadow sets).
        self._scope_stack = []
        self._comp_shadow_stack = []
        # Precomputed per-function mappings (id(node) -> mapping) and the
        # call-site registry (function name -> {param: renamed}).
        # Built by _build_registry() in visit_Module, before traversal.
        self._precomputed = {}
        self._registry = {}

    def _new_name(self, taken):
        while True:
            name = "_s%04x" % (self._offset + self._counter)
            self._counter += 1
            if name not in taken:
                return name

    # -- scope helpers -------------------------------------------------
    def _lookup(self, name):
        # Innermost scope wins (shadowing).
        for mapping in reversed(self._scope_stack):
            if name in mapping:
                return mapping[name]
        return None

    def _is_shadowed_by_comprehension(self, name):
        return any(name in s for s in self._comp_shadow_stack)

    # -- visitors ------------------------------------------------------
    def visit_Module(self, node):
        self._imported = _module_imported_names(node)
        self._build_registry(node)
        self.generic_visit(node)
        return node

    def _build_registry(self, tree):
        """Precompute every function's rename mapping, in module order.

        The mappings must match what the traversal would compute, so
        definitions are collected in depth-first source order and the
        rename counter is consumed exactly as ``_visit_function``
        would consume it (outer function before its nested functions,
        siblings in source order). ``_visit_function`` reuses the
        precomputed mapping instead of recomputing it.

        The registry maps unambiguous plain-function names to their
        parameter renames, so ``visit_Call`` can rename keyword
        arguments at the call site. Excluded from the registry (and
        their parameters are left unrenamed):
          * functions whose name is defined twice in the module — the
            callee is ambiguous, so renaming either definition's
            parameters could break a keyword call;
          * functions called with a non-literal ``**`` unpacking
            (``f(**d)``) — the runtime dict keys cannot be rewritten;
          * functions aliased by direct assignment (``g = f``) — a
            keyword call through the alias cannot be rewritten, because
            the callee name is not in the registry;
          * methods (functions directly inside a ClassDef) — attribute
            calls are never rewritten at the call site (an external
            object could have a same-named method), so a method
            parameter whose name is used as a keyword argument
            anywhere in the module, or belonging to a method called
            via an attribute with keywords (named or ``**``), is left
            unrenamed.
        """
        funcs = []  # (node, is_method) in depth-first source order
        name_counts = {}

        def _collect(node, parent_is_class):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                funcs.append((node, parent_is_class))
                name_counts[node.name] = name_counts.get(node.name, 0) + 1
            for child in ast.iter_child_nodes(node):
                _collect(child, isinstance(node, ast.ClassDef))

        _collect(tree, False)

        # Keyword argument names used anywhere, and method names called
        # via an attribute with keywords.
        all_kwarg_names = set()
        attr_methods_with_kwargs = set()
        # Callees called with a non-literal ** unpacking (``f(**d)``):
        # the runtime dict keys cannot be rewritten, so the callee's
        # parameters must stay unrenamed or the call breaks. And
        # functions aliased by direct assignment (``g = f``): a keyword
        # call through the alias cannot be rewritten either, because
        # the callee name is not in the registry.
        starstar_callees = set()
        aliased = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                for kw in node.keywords:
                    if kw.arg is not None:
                        all_kwarg_names.add(kw.arg)
                if isinstance(node.func, ast.Attribute) and node.keywords:
                    # Named kwargs or a ** unpacking: either way the
                    # method may be called with keyword arguments.
                    attr_methods_with_kwargs.add(node.func.attr)
                if isinstance(node.func, ast.Name):
                    for kw in node.keywords:
                        if kw.arg is None and not isinstance(kw.value, ast.Dict):
                            starstar_callees.add(node.func.id)
            if isinstance(node, (ast.Assign, ast.AnnAssign)):
                value = node.value
                if (value is not None and isinstance(value, ast.Name)
                        and value.id in name_counts):
                    aliased.add(value.id)

        for node, is_method in funcs:
            mapping = self._function_mapping(node)
            params = (
                list(node.args.posonlyargs) + list(node.args.args)
                + list(node.args.kwonlyargs)
            )
            if node.args.vararg is not None:
                params.append(node.args.vararg)
            if node.args.kwarg is not None:
                params.append(node.args.kwarg)
            param_names = {a.arg for a in params}
            if is_method:
                for name in list(mapping):
                    if name in param_names and (
                        name in all_kwarg_names
                        or node.name in attr_methods_with_kwargs
                    ):
                        del mapping[name]
            elif (name_counts[node.name] > 1
                    or node.name in starstar_callees
                    or node.name in aliased):
                for name in list(mapping):
                    if name in param_names:
                        del mapping[name]
            else:
                self._registry[node.name] = {
                    name: new for name, new in mapping.items()
                    if name in param_names
                }
            self._precomputed[id(node)] = mapping

    def _function_mapping(self, node):
        assigned = _names_assigned_direct(node)
        used = _all_name_ids_direct(node)
        nested_refs = _names_referenced_in_nested(node)

        # global / nonlocal declarations in this scope.
        declared = set()
        for child in ast.walk(node):
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef,
                                  ast.ClassDef)) and child is not node:
                continue
            if isinstance(child, (ast.Global, ast.Nonlocal)):
                declared.update(child.names)
        # String literals in the function: a local whose name appears as
        # a whole word inside ANY string could be looked up dynamically
        # (eval/exec/getattr/globals with a compound expression) — be safe.
        string_values = set()
        for child in ast.walk(node):
            if isinstance(child, ast.Constant) and isinstance(child.value, str):
                string_values.add(child.value)

        taken = set(used) | set(assigned) | set(self._imported)
        mapping = {}
        for name in sorted(assigned):
            if name in _NEVER_RENAME:
                continue
            if _is_dunder(name) or name.startswith("__"):
                continue
            if name in self._imported:
                continue
            if name in declared:
                continue
            if name in nested_refs:
                continue
            if any(re.search(r"\b%s\b" % re.escape(name), s)
                   for s in string_values):
                continue
            # The name must actually be used as a local (assigned names
            # are); also never rename a name that is only a parameter
            # name colliding with an attribute etc. — covered by `taken`.
            new = self._new_name(taken)
            taken.add(new)
            mapping[name] = new
        return mapping

    def _visit_function(self, node):
        # Visit decorators / defaults / annotations first: they are
        # evaluated in the enclosing scope, so the new mapping must NOT
        # apply to them.
        node.decorator_list = [self.visit(d) for d in node.decorator_list]
        if node.returns is not None:
            node.returns = self.visit(node.returns)
        node.args.defaults = [
            self.visit(d) if d is not None else None for d in node.args.defaults
        ]
        node.args.kw_defaults = [
            self.visit(d) if d is not None else None for d in node.args.kw_defaults
        ]
        for arg in (
            list(node.args.posonlyargs) + list(node.args.args)
            + list(node.args.kwonlyargs)
        ):
            if arg.annotation is not None:
                arg.annotation = self.visit(arg.annotation)
        if node.args.vararg is not None and node.args.vararg.annotation is not None:
            node.args.vararg.annotation = self.visit(node.args.vararg.annotation)
        if node.args.kwarg is not None and node.args.kwarg.annotation is not None:
            node.args.kwarg.annotation = self.visit(node.args.kwarg.annotation)

        mapping = self._precomputed.get(id(node))
        if mapping is None:
            # Not reached via visit_Module (e.g. visiting a lone
            # function node): compute the mapping on the spot.
            mapping = self._function_mapping(node)
        self._scope_stack.append(mapping)
        # Rename parameter names themselves.
        for arg in (
            list(node.args.posonlyargs) + list(node.args.args)
            + list(node.args.kwonlyargs)
        ):
            if arg.arg in mapping:
                arg.arg = mapping[arg.arg]
        if node.args.vararg is not None and node.args.vararg.arg in mapping:
            node.args.vararg.arg = mapping[node.args.vararg.arg]
        if node.args.kwarg is not None and node.args.kwarg.arg in mapping:
            node.args.kwarg.arg = mapping[node.args.kwarg.arg]
        node.body = [self.visit(stmt) for stmt in node.body]
        self._scope_stack.pop()
        return node

    def visit_FunctionDef(self, node):
        return self._visit_function(node)

    def visit_AsyncFunctionDef(self, node):
        return self._visit_function(node)

    def visit_Lambda(self, node):
        # Lambdas: defaults in enclosing scope, body in lambda scope.
        node.args.defaults = [
            self.visit(d) if d is not None else None for d in node.args.defaults
        ]
        node.args.kw_defaults = [
            self.visit(d) if d is not None else None for d in node.args.kw_defaults
        ]
        # Lambda parameters are deliberately NOT renamed: a lambda is
        # usually bound to a name and may be called with keyword
        # arguments (``f = lambda x: ...; f(x=1)``), and there is no
        # registry entry for a lambda, so renaming a parameter would
        # break the keyword call. The identity mapping keeps each
        # parameter shadowing any same-named enclosing local, so body
        # references still resolve to the parameter; references to
        # renamed enclosing locals still resolve through the stack.
        params = (
            list(node.args.posonlyargs) + list(node.args.args)
            + list(node.args.kwonlyargs)
        )
        if node.args.vararg is not None:
            params.append(node.args.vararg)
        if node.args.kwarg is not None:
            params.append(node.args.kwarg)
        self._scope_stack.append({a.arg: a.arg for a in params})
        node.body = self.visit(node.body)
        self._scope_stack.pop()
        return node

    def visit_comprehension(self, node):
        # The iterator is evaluated in the enclosing scope; the target
        # and conditions live in the comprehension's own scope, where a
        # target name shadows any outer local of the same name.
        node.iter = self.visit(node.iter)
        shadow = set()

        def _target_names(target):
            if isinstance(target, ast.Name):
                shadow.add(target.id)
            elif isinstance(target, (ast.Tuple, ast.List)):
                for elt in target.elts:
                    _target_names(elt)
            elif isinstance(target, ast.Starred):
                _target_names(target.value)

        _target_names(node.target)
        self._comp_shadow_stack.append(shadow)
        node.target = self.visit(node.target)
        node.ifs = [self.visit(c) for c in node.ifs]
        self._comp_shadow_stack.pop()
        return node

    # Comprehension element/key/value expressions are evaluated after
    # the targets are bound, but ast field order visits them BEFORE the
    # generators — so visit them manually, with all target shadows
    # active, after visiting each generator's iter/target/ifs.
    def _visit_comp(self, node, elt_fields):
        for gen in node.generators:
            gen.iter = self.visit(gen.iter)
            shadow = set()

            def _target_names(target, _shadow=shadow):
                if isinstance(target, ast.Name):
                    _shadow.add(target.id)
                elif isinstance(target, (ast.Tuple, ast.List)):
                    for elt in target.elts:
                        _target_names(elt, _shadow)
                elif isinstance(target, ast.Starred):
                    _target_names(target.value, _shadow)

            _target_names(gen.target)
            self._comp_shadow_stack.append(shadow)
            gen.target = self.visit(gen.target)
            gen.ifs = [self.visit(c) for c in gen.ifs]
        for field in elt_fields:
            setattr(node, field, self.visit(getattr(node, field)))
        for _ in node.generators:
            self._comp_shadow_stack.pop()
        return node

    def visit_ListComp(self, node):
        return self._visit_comp(node, ["elt"])

    def visit_SetComp(self, node):
        return self._visit_comp(node, ["elt"])

    def visit_GeneratorExp(self, node):
        return self._visit_comp(node, ["elt"])

    def visit_DictComp(self, node):
        return self._visit_comp(node, ["key", "value"])

    def visit_Name(self, node):
        if self._is_shadowed_by_comprehension(node.id):
            return node
        new = self._lookup(node.id)
        if new is not None:
            node.id = new
        return node

    def visit_Call(self, node):
        # Keyword arguments are plain strings, never Name nodes, so the
        # callee's parameter renames must be applied here explicitly.
        # Only when the callee is a bare Name that is NOT a renamed
        # local (i.e. it resolves to a module-level binding) and is in
        # the registry: a local (closure variable, shadowing assignment,
        # lambda) must not get registry treatment. Attribute calls
        # (obj.method(...)) are never rewritten here — see
        # _build_registry for how method parameters are protected.
        registry_mapping = None
        if isinstance(node.func, ast.Name):
            callee = node.func.id
            if self._lookup(callee) is None:
                registry_mapping = self._registry.get(callee)
        node = self.generic_visit(node)
        if registry_mapping:
            for kw in node.keywords:
                if kw.arg is not None and kw.arg in registry_mapping:
                    kw.arg = registry_mapping[kw.arg]
                elif kw.arg is None and isinstance(kw.value, ast.Dict):
                    # Literal-dict ** unpacking: rename matching keys.
                    for key in kw.value.keys:
                        if (isinstance(key, ast.Constant)
                                and isinstance(key.value, str)
                                and key.value in registry_mapping):
                            key.value = registry_mapping[key.value]
        return node

    def visit_MatchAs(self, node):
        # Capture bindings are plain strings, like except-handler names:
        # rename them via the enclosing scope's mapping.
        if node.name:
            new = self._lookup(node.name)
            if new is not None:
                node.name = new
        self.generic_visit(node)
        return node

    def visit_MatchStar(self, node):
        if node.name:
            new = self._lookup(node.name)
            if new is not None:
                node.name = new
        self.generic_visit(node)
        return node

    def visit_MatchMapping(self, node):
        if node.rest:
            new = self._lookup(node.rest)
            if new is not None:
                node.rest = new
        self.generic_visit(node)
        return node

    def visit_ExceptHandler(self, node):
        # The handler name is a local binding of the enclosing function;
        # generic_visit would rename it via visit_Name only if it is a
        # Name node — in ast it is a plain string, so rename it here.
        if node.name:
            new = self._lookup(node.name)
            if new is not None:
                node.name = new
        self.generic_visit(node)
        return node


# ---------------------------------------------------------------------------
# String encryption
# ---------------------------------------------------------------------------

class StringEncryptTransformer(ast.NodeTransformer):
    """Replace plain str constants with ``shroud_runtime.dec("<b64>")``.

    Skips docstrings, f-strings, annotation strings and dict keys
    (see ``_skip_ids_for_strings``). F-strings are left entirely alone:
    encrypting their parts would change formatting behaviour.
    """

    def __init__(self, key: bytes):
        super().__init__()
        self._key = key
        self._skip = set()

    def visit_Module(self, node):
        self._skip = _skip_ids_for_strings(node)
        self.generic_visit(node)
        return node

    def visit_JoinedStr(self, node):
        # Leave f-strings untouched (including any nested expressions
        # that happen to contain plain strings).
        return node

    def visit_Constant(self, node):
        if isinstance(node.value, str) and id(node) not in self._skip:
            encoded = encrypt_string(node.value, self._key)
            new = _make_dec_call(encoded)
            return ast.copy_location(new, node)
        return node


# ---------------------------------------------------------------------------
# Literal encoding
# ---------------------------------------------------------------------------

class LiteralEncodeTransformer(ast.NodeTransformer):
    """Encode int constants as simple arithmetic expressions.

    e.g. 42 -> (21 + 21). ``ast.unparse`` renders ints in decimal, so a
    hex literal cannot survive an AST round-trip; arithmetic is the
    honest equivalent. Skips True/False/None, dict keys and annotation
    ints. Ints 0 and 1 are left alone (encoding them adds only noise).
    """

    def __init__(self, seed=None):
        super().__init__()
        self._rng = random.Random(seed) if seed is not None else random.Random()
        self._skip = set()

    def visit_Module(self, node):
        self._skip = _skip_ids_for_ints(node)
        self.generic_visit(node)
        return node

    def visit_Constant(self, node):
        if type(node.value) is int and id(node) not in self._skip:
            value = node.value
            if abs(value) >= 2:
                if value > 2:
                    a = self._rng.randrange(1, value)
                else:  # value == 2
                    a = 1
                b = value - a
                expr = ast.BinOp(
                    left=ast.Constant(value=a),
                    op=ast.Add(),
                    right=ast.Constant(value=b),
                )
                return ast.copy_location(expr, node)
        return node


# ---------------------------------------------------------------------------
# Control-flow flattening
# ---------------------------------------------------------------------------

def _has_yield_or_await_direct(func):
    """True if ``func``'s own body (not nested funcs) yields."""
    found = False

    def _visit(node):
        nonlocal found
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef,
                             ast.ClassDef, ast.Lambda)) and node is not func:
            return
        if isinstance(node, (ast.Yield, ast.YieldFrom)):
            found = True
            return
        for child in ast.iter_child_nodes(node):
            _visit(child)

    for stmt in func.body:
        _visit(stmt)
    return found


def _has_global_nonlocal_direct(func):
    found = False

    def _visit(node):
        nonlocal found
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef,
                             ast.ClassDef, ast.Lambda)) and node is not func:
            return
        if isinstance(node, (ast.Global, ast.Nonlocal)):
            found = True
            return
        for child in ast.iter_child_nodes(node):
            _visit(child)

    for stmt in func.body:
        _visit(stmt)
    return found


def _unused_name(base, tree):
    used = {n.id for n in ast.walk(tree) if isinstance(n, ast.Name)}
    used |= {n.name for n in ast.walk(tree)
             if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))}
    used |= {a.arg for n in ast.walk(tree) if isinstance(n, ast.arg) for a in [n]}
    name = base
    i = 1
    while name in used:
        name = "%s_%d" % (base, i)
        i += 1
    return name


class FlattenTransformer(ast.NodeTransformer):
    """Rewrite a function body into ``while True:`` + state dispatch.

    Each top-level statement becomes one chunk (a ``try``/``with``/
    ``for``/``if`` statement is one chunk, its inner body intact).
    Top-level ``return`` becomes ``__ret = <expr>; __state = <exit>``.
    Returns nested inside a chunk are left as plain ``return`` — they
    exit the function directly, which is behaviour-preserving.

    Skipped entirely: generator functions (any ``yield``), async
    functions, and functions containing ``global``/``nonlocal``.
    A leading docstring is kept in place (before the loop) so
    ``__doc__`` is preserved.
    """

    def visit_FunctionDef(self, node):
        node = self._flatten(node)
        # Still visit nested functions so they get flattened too.
        self.generic_visit(node)
        return node

    def visit_AsyncFunctionDef(self, node):
        # Async functions are never flattened.
        self.generic_visit(node)
        return node

    def _flatten(self, node):
        if _has_yield_or_await_direct(node):
            return node
        if _has_global_nonlocal_direct(node):
            return node

        body = list(node.body)
        doc = None
        if body:
            doc_node = _docstring_node(body)
            if doc_node is not None:
                doc = body[0]
                body = body[1:]
        if not body:
            return node

        state_name = _unused_name("__state", node)
        ret_name = _unused_name("__ret", node)
        n_chunks = len(body)
        exit_state = n_chunks  # any state not in the dispatch -> break

        def _state_assign(value):
            return ast.Assign(
                targets=[ast.Name(id=state_name, ctx=ast.Store())],
                value=ast.Constant(value=value),
            )

        def _ret_assign(value):
            return ast.Assign(
                targets=[ast.Name(id=ret_name, ctx=ast.Store())],
                value=value if value is not None else ast.Constant(value=None),
            )

        # Build the if/elif dispatch chain from the last chunk backwards.
        # Final else-branch: break.
        else_branch = [ast.Break()]
        chain = None
        for idx in range(n_chunks - 1, -1, -1):
            stmt = body[idx]
            if isinstance(stmt, ast.Return):
                chunk_body = [_ret_assign(stmt.value), _state_assign(exit_state)]
            else:
                chunk_body = [stmt, _state_assign(idx + 1)]
            test = ast.Compare(
                left=ast.Name(id=state_name, ctx=ast.Load()),
                ops=[ast.Eq()],
                comparators=[ast.Constant(value=idx)],
            )
            if_node = ast.If(test=test, body=chunk_body, orelse=[])
            if chain is None:
                # Outermost built so far is the last chunk; attach else.
                if_node.orelse = else_branch
                chain = if_node
            else:
                if_node.orelse = [chain]
                chain = if_node

        loop = ast.While(
            test=ast.Constant(value=True),
            body=[chain],
            orelse=[],
        )
        new_body = []
        if doc is not None:
            new_body.append(doc)
        new_body.append(
            ast.Assign(
                targets=[ast.Name(id=state_name, ctx=ast.Store())],
                value=ast.Constant(value=0),
            )
        )
        new_body.append(
            ast.Assign(
                targets=[ast.Name(id=ret_name, ctx=ast.Store())],
                value=ast.Constant(value=None),
            )
        )
        new_body.append(loop)
        new_body.append(
            ast.Return(value=ast.Name(id=ret_name, ctx=ast.Load()))
        )
        node.body = new_body
        return node


# ---------------------------------------------------------------------------
# Dead-code injection
# ---------------------------------------------------------------------------

def add_dead_code(tree, seed=None):
    """Add side-effect-free dead code: ``if False:`` blocks and one
    never-called junk function per file.

    Junk is syntactically valid and side-effect-free (constant arithmetic
    assigned to fresh names). Returns the tree.
    """
    rng = random.Random(seed) if seed is not None else random.Random()
    used = {n.id for n in ast.walk(tree) if isinstance(n, ast.Name)}
    used |= {n.name for n in ast.walk(tree)
             if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))}

    def _fresh(prefix):
        i = 0
        while True:
            name = "%s%d" % (prefix, i)
            i += 1
            if name not in used:
                used.add(name)
                return name

    def _junk_assignments(count):
        stmts = []
        for _ in range(count):
            name = _fresh("_shroud_dead_")
            a = rng.randrange(1, 1000)
            b = rng.randrange(1, 1000)
            stmts.append(
                ast.Assign(
                    targets=[ast.Name(id=name, ctx=ast.Store())],
                    value=ast.BinOp(
                        left=ast.Constant(value=a),
                        op=ast.Add(),
                        right=ast.Constant(value=b),
                    ),
                )
            )
        return stmts

    def _if_false_block():
        return ast.If(
            test=ast.Constant(value=False),
            body=_junk_assignments(3),
            orelse=[],
        )

    # One `if False:` block at module level.
    tree.body.append(_if_false_block())

    # One `if False:` block at the top of each function (after a
    # docstring, if present), including methods and nested functions.
    for node in list(ast.walk(tree)):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            # Skip the junk function itself (added below, so not present yet).
            insert_at = 1 if _docstring_node(node.body) is not None else 0
            node.body.insert(insert_at, _if_false_block())

    # One never-called junk function per file.
    junk_name = _fresh("_shroud_junk_")
    junk_fn = ast.FunctionDef(
        name=junk_name,
        args=ast.arguments(
            posonlyargs=[], args=[], vararg=None, kwonlyargs=[],
            kw_defaults=[], kwarg=None, defaults=[],
        ),
        body=_junk_assignments(2) + [ast.Return(value=ast.Constant(value=None))],
        decorator_list=[],
    )
    tree.body.append(junk_fn)
    return tree
