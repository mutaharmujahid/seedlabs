#include <stdio.h>
#include <openssl/bn.h>

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
    BIGNUM *S = BN_new();
    BIGNUM *C = BN_new();

    char n_str[2048], e_str[10], M_str[1024], S_str[1024];

    // Input for Public Key and Signature
    printf("*** Modified Code for Task 6 ***\n");
    printf("Enter Public Key: \n");
    printf("\te (DECIMAL): ");
    scanf("%s", e_str);
    printf("\tn (HEX): ");
    scanf("%s", n_str);

    printf("Enter Hash Value (HEX): ");
    scanf("%s", M_str);

    printf("Enter Signature to be Verified (HEX): ");
    scanf("%s", S_str);

    // Convert inputs to BIGNUM format
    BN_hex2bn(&n, n_str);
    BN_dec2bn(&e, e_str);
    BN_hex2bn(&M, M_str);
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