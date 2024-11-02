from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

def main():
    ascii_plaintext = input("Enter plaintext (total 21 characters): ")
    if len(ascii_plaintext) != 21:
        raise ValueError("The plaintext must be exactly 21 characters long.")

    hex_ciphertext = input("Enter ciphertext (in hex format): ")
    hex_iv = input("Enter IV (in hex format): ")
    plaintext = ascii_plaintext.encode('ascii')
    ciphertext = bytes.fromhex(hex_ciphertext)
    iv = bytes.fromhex(hex_iv)

    with open('words.txt') as file:
        words = file.read().splitlines()

    for word in words:
        if len(word) <= 16:
            padded_word = word.ljust(16, '#')
            word_bytes = padded_word.encode('ascii')
            cipher = AES.new(word_bytes, AES.MODE_CBC, iv)
            encrypted_text = cipher.encrypt(pad(plaintext, AES.block_size))
            if encrypted_text == ciphertext:
                # Remove padding from the key
                original_key = padded_word.rstrip('#')
                print(f"Found key: {original_key}")
                return
    print("No matching key found.")

if __name__ == "__main__":
    main()

