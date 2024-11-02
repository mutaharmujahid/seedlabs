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
    BIGNUM *e = BN_new();
    BIGNUM *M = BN_new();
    BIGNUM *S = BN_new();
    BIGNUM *C = BN_new();

    // Input for Alice's Public Key and Signature
    char n_str[NBITS], e_str[NBITS], ascii_msg[NBITS], S_str[NBITS];

    printf("Enter Alice's Public Key: \n");
    printf("\te (DECIMAL): ");
    scanf("%s", e_str);
    printf("\tn (HEX): ");
    scanf("%s", n_str);

    printf("Enter Message (ASCII): ");
    getchar();
    fgets(ascii_msg, NBITS, stdin);
    ascii_msg[strcspn(ascii_msg, "\n")] = 0;

    printf("Enter Signature provided by Alice (HEX): ");
    scanf("%s", S_str);

    // Convert inputs to BIGNUM format
    BN_hex2bn(&n, n_str);
    BN_dec2bn(&e, e_str);
    ascii_to_bn(M, ascii_msg);
    BN_hex2bn(&S, S_str);

    // Signature verification: C = S^e mod n
    BN_mod_exp(C, S, e, n, ctx);

    // Compare the calculated ciphertext C with the original message M
    if (BN_cmp(C, M) == 0)
    {
        printf("Signature is verified & valid.\n");
    }
    else
    {
        printf("Signature is corrupted & invalid.\n");
    }

    // Clear all data and free allocated memory
    BN_clear_free(n);
    BN_clear_free(e);
    BN_clear_free(M);
    BN_clear_free(S);
    BN_clear_free(C);
    BN_CTX_free(ctx);

    return 0;
}
