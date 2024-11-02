#!/usr/bin/python3

# XOR two bytearrays
def xor(first, second):
   return bytearray(x^y for x,y in zip(first, second))

 
MSG1 = input("Enter Plaintext (P1): ")
HEX_1 = input("Enter Ciphertext (C1): ")

# Convert ascii string to bytearray
D1 = bytes(MSG1, 'utf-8')
HEX_2 = input("Enter Ciphertext (C2): ")

# Convert hex string to bytearray
D2 = bytearray.fromhex(HEX_1)
D3 = bytearray.fromhex(HEX_2)

r1 = xor(D1, D2)
print("Key = P1 XOR C1 = ",r1.hex())
r2 = xor(r1, D3)
print("P2 = Key XOR C2 = ",r2.hex(),"\nPlaintext P2 in ASCII: ",r2.decode("ASCII"))
