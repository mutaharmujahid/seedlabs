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

void ascii_to_bn(BIGNUM *bn, const char *ascii)
{
    char hex_str[NBITS * 2 + 1];
    int i;

    for (i = 0; i < strlen(ascii); i++)
    {
        sprintf(hex_str + i * 2, "%02x", ascii[i]);
    }
    hex_str[i * 2] = '\0';
    BN_hex2bn(&bn, hex_str);
}

int main()
{
    BN_CTX *ctx = BN_CTX_new();
    BIGNUM *n = BN_new();
    BIGNUM *d = BN_new();
    BIGNUM *M1 = BN_new();
    BIGNUM *M2 = BN_new();
    BIGNUM *C1 = BN_new();
    BIGNUM *C2 = BN_new();

    // RSA parameters (n and d) are set
    BN_hex2bn(&n, "DCBFFE3E51F62E09CE7032E2677A78946A849DC4CDDE3A4D0CB81629242FB1A5");
    BN_hex2bn(&d, "74D806F9F3A62BAE331FFE3F0A68AFE35B3D2E4794148AACBC26AA381CD7D30D");

    // Input for the messages
    char ascii_M1[NBITS], ascii_M2[NBITS];
    printf("Enter M1 (ASCII): ");
    fgets(ascii_M1, NBITS, stdin);
    ascii_M1[strcspn(ascii_M1, "\n")] = 0;

    printf("Enter M2 (ASCII): ");
    fgets(ascii_M2, NBITS, stdin);
    ascii_M2[strcspn(ascii_M2, "\n")] = 0;
    ascii_to_bn(M1, ascii_M1);
    ascii_to_bn(M2, ascii_M2);
    // RSA signature: C = M^d mod n
    BN_mod_exp(C1, M1, d, n, ctx);
    BN_mod_exp(C2, M2, d, n, ctx);

    // Print the signatures of both the messages in hex format
    printBN("Signature of M1 (hex):", C1);
    printBN("Signature of M2 (hex):", C2);

    // Clear all data and free allocated memory
    BN_clear_free(n);
    BN_clear_free(d);
    BN_clear_free(M1);
    BN_clear_free(M2);
    BN_clear_free(C1);
    BN_clear_free(C2);
    BN_CTX_free(ctx);

    return 0;
}
