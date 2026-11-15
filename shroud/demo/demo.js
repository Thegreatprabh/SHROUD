// SHROUD demo program (JavaScript).
// DOM-free: strings, arithmetic, control flow, functions, arrays.
// Output is deterministic — the protected file must print exactly this.

function add(a, b) {
  return a + b;
}

function multiply(a, b) {
  return a * b;
}

function greet(name) {
  return "Hello, " + name + "!";
}

function describeScore(score) {
  if (score >= 90) {
    return "excellent";
  } else if (score >= 60) {
    return "good";
  } else {
    return "needs work";
  }
}

var numbers = [3, 1, 4, 1, 5, 9, 2, 6];
var total = 0;
var evens = [];
for (var i = 0; i < numbers.length; i++) {
  total = add(total, numbers[i]);
  if (numbers[i] % 2 === 0) {
    evens.push(numbers[i]);
  }
}

var doubled = [];
for (var j = 0; j < numbers.length; j++) {
  doubled.push(multiply(numbers[j], 2));
}

console.log(greet("World"));
console.log("numbers: " + numbers.join(", "));
console.log("sum: " + total);
console.log("average: " + total / numbers.length);
console.log("evens: " + evens.join(", "));
console.log("doubled: " + doubled.join(", "));
console.log("product of 6 and 7: " + multiply(6, 7));
console.log("score 85 is " + describeScore(85));
console.log("score 42 is " + describeScore(42));
console.log("done");
