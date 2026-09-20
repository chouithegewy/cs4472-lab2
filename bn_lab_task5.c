/**
 * @file bn_lab_task5.c
 * @brief CS4472 Lab 2 - deriving an RSA private key with the OpenSSL BIGNUM API.
 */
#include <assert.h>
#include <openssl/bn.h>
#include <stdio.h>

void printBNStr(char *msg, BIGNUM *a) {
    char *number_str = BN_bn2hex(a);
    printf("%s %s\n", msg, number_str);
    OPENSSL_free(number_str);
}

int main() {
    BN_CTX *ctx = BN_CTX_new();
    // task 3.5 - veryifying a signature
    char *n_hex = "AE1CD4DC432798D933779FBD46C6E1247F0CF1233595113AA51B450F18116115";
    char *e_hex = "010001"; //  (this hex value equals to decimal 65537)
    //char *s_hex = "643D6F34902D9C7EC90CB0B2BCA36C47FA37165C0005CAB026C0542CBDB6802F";
    char *s_hex = "643D6F34902D9C7EC90CB0B2BCA36C47FA37165C0005CAB026C0542CBDB6803F"; // corrupted
    //char *M_str = "Launch a missle";
    // python3 -c 'print("Launch a missle.".encode("utf-8").hex())'
    char *M_hex = "4c61756e63682061206d6973736c652e";

    BIGNUM *M = BN_new();
    BIGNUM *n = BN_new();
    BIGNUM *e = BN_new();
    BIGNUM *S = BN_new();
    BIGNUM *v = BN_new();

    BN_hex2bn(&n, n_hex);
    BN_hex2bn(&e, e_hex);
    BN_hex2bn(&M, M_hex);
    BN_hex2bn(&S, s_hex);

    // veryifying that the signed message S is indeed encrypted by Alice's private key d
    // that is, that she is the author of the message
    BN_mod_exp(v, S, e, n, ctx);

    printBNStr("v (hex):", v);

    BN_free(M);
    BN_free(n);
    BN_free(e);
    BN_free(S);
    BN_CTX_free(ctx);

    return 0;
}
