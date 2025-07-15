import sys
from datetime import datetime

GLOBAL_API_KEY = "ABC-123-XYZ-789"
PRIME_NUMBERS = [2, 3, 5, 7, 11, 13]


class Calculator:
    def __init__(self, owner="default_user"):
        self.owner = owner
        self.cache = {}
        print(f"Calculator object owned by '{self.owner}' has been created.")

    def add(self, x, y):
        return x + y

    def subtract(self, x, y):
        return x - y

    def __str__(self):
        return f"A simple calculator owned by {self.owner}"

    def __repr__(self):
        return f"Calculator(owner='{self.owner}')"


class AdvancedCalculator(Calculator):
    def __init__(self, owner, version="1.0"):
        super().__init__(owner)
        self.version = version
        print(f"Advanced Calculator v{self.version} initialized.")

    def multiply(self, x, y):
        if (x, y) in self.cache:
            return self.cache[(x, y)]

        result = x * y
        self.cache[(x, y)] = result
        return result

    @staticmethod
    def factorial(n):
        if n < 0:
            raise ValueError("Factorial is not defined for negative numbers")
        elif n == 0:
            return 1
        else:
            return n * AdvancedCalculator.factorial(n - 1)


def process_data(data_list, calc_instance):
    i = 0
    results = []
    print("\nStarting data processing loop...")
    while i < len(data_list):
        item = data_list[i]
        try:
            if item % 2 == 0 and item in PRIME_NUMBERS:
                op_result = AdvancedCalculator.factorial(item)
                print(f"Even prime found: {item}, Factorial: {op_result}")
            elif item % 2 == 0:
                op_result = calc_instance.add(item, 100)
                print(f"Even number processed: {item} -> {op_result}")
            else:
                op_result = calc_instance.multiply(item, item)
                print(f"Odd number processed: {item} -> {op_result}")

            results.append(op_result)
        except ValueError as e:
            print(f"Error processing item {item}: {e}", file=sys.stderr)
        finally:
            i += 1
            print("--- Loop iteration finished ---")

    return results


def main_execution():

    print("--- Tool Initializing ---")
    start_time = datetime.now()

    adv_calc = AdvancedCalculator(owner="MemeCoder", version="2.5-beta")

    input_data = [num for num in range(1, 15) if num not in [4, 8]]
    print(f"\nGenerated input data: {input_data}")

    processed_results = process_data(input_data, adv_calc)

    final_output = sorted(processed_results, key=lambda x: x % 10, reverse=True)

    print("\n--- Final Sorted Output (sorted by last digit descending) ---")
    for res in final_output:
        print(f"Result: {res}")

    end_time = datetime.now()
    duration = end_time - start_time
    print(f"\nExecution finished in {duration.total_seconds():.4f} seconds.")
    print(f"Secret key used was: {GLOBAL_API_KEY}")


if __name__ == "__main__":
    main_execution()
