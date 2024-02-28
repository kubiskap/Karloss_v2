def bytes_to_bits(bytes_value, num_bits):
    binary_string = ''.join(format(byte, '08b') for byte in bytes_value)
    return binary_string[:num_bits]


def bits_to_bytes(binary_string):
    # Ensure binary string is padded to a multiple of 8
    binary_string = binary_string.zfill((len(binary_string) + 7) // 8 * 8)

    bytes_value = bytes(int(binary_string[i:i + 8], 2) for i in range(0, len(binary_string), 8))
    return bytes_value


# Example usage:
input_bytes = b'\x80'
num_bits = 2

binary_result = bytes_to_bits(input_bytes, num_bits)
print(binary_result)  # Output: '10'

bytes_result = bits_to_bytes(binary_result)
print(bytes_result)  # Output: b'\x80'