/**
 * @file bn_lab_task2.c
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
    // task 3.2 - encrypting a message
    char *n_hex = "DCBFFE3E51F62E09CE7032E2677A78946A849DC4CDDE3A4D0CB81629242FB1A5";
    char *e_hex = "010001"; //  (this hex value equals to decimal 65537)
    char *d_hex = "74D806F9F3A62BAE331FFE3F0A68AFE35B3D2E4794148AACBC26AA381CD7D30D";
    // char *M_str = "A top secret!"; // plaintext
    //  python3 -c 'print("A top secret!".encode("utf-8").hex())'
    char *M_hex = "4120746f702073656372657421";

    BIGNUM *M = BN_new();
    BIGNUM *n = BN_new();
    BIGNUM *e = BN_new();
    BIGNUM *d = BN_new();
    BIGNUM *C = BN_new();

    BN_hex2bn(&n, n_hex);
    BN_hex2bn(&d, d_hex);
    BN_hex2bn(&e, e_hex);
    BN_hex2bn(&M, M_hex);

    // C = M^e mod n
    BN_mod_exp(C, M, e, n, ctx);

    printBNStr("ciphertext (hex):", C);

    // verifying answer
    // so C^d mod n should = M
    BIGNUM *res = BN_new();
    BN_mod_exp(res, C, d, n, ctx);
    printBNStr("plaintext (hex)", res);

    BN_free(M);
    BN_free(n);
    BN_free(d);
    BN_free(e);
    BN_free(C);
    BN_free(res);
    BN_CTX_free(ctx);

    return 0;
}
