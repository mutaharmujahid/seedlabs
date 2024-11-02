#include <stdio.h>
#include <openssl/bn.h>

#define NBITS 256

void printBN(char *msg, BIGNUM *a)
{
    char *number_str_a = BN_bn2hex(a);
    printf("%s %s\n", msg, number_str_a);
    OPENSSL_free(number_str_a);
}

int main()
{
    BN_CTX *ctx = BN_CTX_new();
    BIGNUM *n = BN_new();
    BIGNUM *e = BN_new();
    BIGNUM *M = BN_new();
    BIGNUM *C = BN_new(); // For ciphertext

    char n_str[NBITS], e_str[NBITS], M_str[NBITS];

    // Take inputs
    printf("Enter value of n (hex): ");
    scanf("%s", n_str);
    printf("Enter value of e (decimal): ");
    scanf("%s", e_str);
    printf("Enter message M to encrypt (hex): ");
    scanf("%s", M_str);

    // Convert all inputs to BIGNUM
    BN_hex2bn(&n, n_str);
    BN_dec2bn(&e, e_str);
    BN_hex2bn(&M, M_str);

    // RSA Encryption: C = M^e mod n
    BN_mod_exp(C, M, e, n, ctx);
    printBN("Cipher Text:", C);

    // Clear all data and free allocated memory
    BN_clear_free(n);
    BN_clear_free(e);
    BN_clear_free(M);
    BN_clear_free(C);
    BN_CTX_free(ctx);

    return 0;
}
