# SHROUD demo program (Python).
# Strings, arithmetic, control flow, functions, dicts/lists, a class.
# Output is deterministic — the protected file must print exactly this.


def add(a, b):
    return a + b


def multiply(a, b):
    return a * b


def greet(name):
    return "Hello, " + name + "!"


def describe_score(score):
    if score >= 90:
        return "excellent"
    elif score >= 60:
        return "good"
    else:
        return "needs work"


class Greeter:
    def __init__(self, name):
        self.name = name

    def message(self):
        return greet(self.name)


def main():
    numbers = [3, 1, 4, 1, 5, 9, 2, 6]
    total = 0
    evens = []
    for n in numbers:
        total = add(total, n)
        if n % 2 == 0:
            evens.append(n)

    doubled = [multiply(n, 2) for n in numbers]

    scores = {"alice": 85, "bob": 42, "carol": 95}
    best = max(scores, key=lambda name: scores[name])

    greeter = Greeter("World")
    print(greeter.message())
    print("numbers: " + ", ".join(str(n) for n in numbers))
    print("sum: " + str(total))
    print("average: " + str(total / len(numbers)))
    print("evens: " + ", ".join(str(n) for n in evens))
    print("doubled: " + ", ".join(str(n) for n in doubled))
    print("product of 6 and 7: " + str(multiply(6, 7)))
    print("score 85 is " + describe_score(85))
    print("score 42 is " + describe_score(42))
    print("best score: " + best + " with " + str(scores[best]))
    print("done")


if __name__ == "__main__":
    main()
