#include <stdio.h>
#include <openssl/bn.h>
#include <string.h>

#define NBITS 256

void printBN(char *msg, BIGNUM *a)
{
    char *number_str_a = BN_bn2hex(a);
    printf("%s %s\n", msg, number_str_a);
    OPENSSL_free(number_str_a);
}

void printBNAsASCII(char *msg, BIGNUM *a)
{
    char *number_str_a = BN_bn2hex(a);
    printf("%s ", msg);
    for (size_t i = 0; i < strlen(number_str_a); i += 2)
    {
        char hex_byte[3] = {number_str_a[i], number_str_a[i+1], '\0'};
        printf("%c", (char)strtol(hex_byte, NULL, 16));
    }
    printf("\n");
    OPENSSL_free(number_str_a);
}

int main()
{
    BN_CTX *ctx = BN_CTX_new();
    BIGNUM *n = BN_new();
    BIGNUM *d = BN_new();
    BIGNUM *C = BN_new();
    BIGNUM *M = BN_new(); // For decrypted message (plaintext)

    char n_str[NBITS], d_str[NBITS], C_str[NBITS];

    // Take inputs
    printf("Enter value of n (hex): ");
    scanf("%s", n_str);
    printf("Enter value of d (hex): ");
    scanf("%s", d_str);
    printf("Enter ciphertext C (hex): ");
    scanf("%s", C_str);

    // Convert all inputs to BIGNUM
    BN_hex2bn(&n, n_str);
    BN_hex2bn(&d, d_str);
    BN_hex2bn(&C, C_str);

    // RSA Decryption M = C^d mod n
    BN_mod_exp(M, C, d, n, ctx);

    // Print the decrypted text in hex and ASCII
    printBN("Decrypted message (hex):", M);
    printBNAsASCII("Decrypted message (ASCII):", M);

    // Clear all data and free allocated memory
    BN_clear_free(n);
    BN_clear_free(d);
    BN_clear_free(C);
    BN_clear_free(M);
    BN_CTX_free(ctx);

    return 0;
}
