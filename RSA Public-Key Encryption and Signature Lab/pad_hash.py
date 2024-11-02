# Read the initial hash from the file "hash"
with open("hash", "r") as file:
    hash_val = file.read().strip()

# Define prefix and algorithm identifier (A)
prefix = "0001"

# SHA 256 Header
A = "3031300D060960864801650304020105000420"

# Total length for RSA (256 bytes)
total_len = 256

# Calculate padding length
pad_len = total_len - 1 - (len(A) + len(prefix) + len(hash_val)) // 2

# Construct the padded message
padded_hash = prefix + "FF" * pad_len + "00" + A + hash_val

# Save the padded hash
with open("padded_hash", "w") as file:
    file.write(padded_hash)

print("Padded hash saved to 'padded_hash'")
print("Padded Hash = ", padded_hash)