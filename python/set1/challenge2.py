hexed_input_string = "1c0111001f010100061a024b53535009181c"
hexed_xor_string = "686974207468652062756c6c277320657965"
hexed_expected_result = "746865206b696420646f6e277420706c6179"

result = hex(int(hexed_input_string, 16) ^ int(hexed_xor_string, 16))

assert result[2:] == hexed_expected_result
