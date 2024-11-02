#include <stdio.h>
#include <openssl/bn.h>

#define NBITS 256

int main()
{
    BN_CTX *ctx = BN_CTX_new();
    BIGNUM *p = BN_new();
    BIGNUM *q = BN_new();
    BIGNUM *n = BN_new();
    BIGNUM *euler_func = BN_new();
    BIGNUM *e = BN_new();
    BIGNUM *d = BN_new();
    BIGNUM *res = BN_new();
    BIGNUM *p_1 = BN_new();
    BIGNUM *q_1 = BN_new();

    char p_str[NBITS], q_str[NBITS], e_str[NBITS];

    printf("Enter value of p (hex): ");
    scanf("%s", p_str);
    printf("Enter value of q (hex): ");
    scanf("%s", q_str);
    printf("Enter value of e (hex): ");
    scanf("%s", e_str);

    BN_hex2bn(&p, p_str);
    BN_hex2bn(&q, q_str);
    BN_hex2bn(&e, e_str);

    // n = p * q
    BN_mul(n, p, q, ctx);

    // Euler's totient function: φ(n) or fai(n) = (p - 1) x (q - 1)
    BN_sub(p_1, p, BN_value_one());
    BN_sub(q_1, q, BN_value_one());
    BN_mul(euler_func, p_1, q_1, ctx);

    // Ensure e and φ(n) or fai(n) are relatively prime
    BN_gcd(res, euler_func, e, ctx);
    if (!BN_is_one(res))
    {
        char *euler_func_str = BN_bn2hex(euler_func);
        char *e_str_converted = BN_bn2hex(e);
        printf("Error: %s and %s are not relatively prime\n", e_str_converted, euler_func_str);
        OPENSSL_free(euler_func_str);
        OPENSSL_free(e_str_converted);
        return 1;
    }

    // Calculate the private key d (modular inverse of e mod φ(n))
    BN_mod_inverse(d, e, euler_func, ctx);

    // Print the private key
    char *private_key_str = BN_bn2hex(d);
    printf("Private key 'd': %s\n", private_key_str);
    OPENSSL_free(private_key_str);

    // Clear and free allocated memory
    BN_clear_free(p);
    BN_clear_free(q);
    BN_clear_free(n);
    BN_clear_free(res);
    BN_clear_free(euler_func);
    BN_clear_free(e);
    BN_clear_free(d);
    BN_clear_free(p_1);
    BN_clear_free(q_1);

    return 0;
}
