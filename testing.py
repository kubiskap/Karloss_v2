from jsonpath_ng import jsonpath, parse

# Example nested data
data = {
    "foo": {
        "bar": {
            "baz": 42
        }
    }
}

# Define JSONPath expression
expr = parse("foo.bar.baz")

# Use JSONPath expression to access value
matches = [match.value for match in expr.find(data)]
print(matches)  # Output: [42]