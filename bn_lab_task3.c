/**
 * @file bn_lab_task3.c
 * @brief CS4472 Lab 2 - deriving an RSA private key with the OpenSSL BIGNUM API.
 */
#include <assert.h>
#include <openssl/bn.h>
#include <stdio.h>


void printBN2Hex(char *msg, BIGNUM *a) {
    char *number_str = BN_bn2hex(a);
    printf("%s %s\n", msg, number_str);
    OPENSSL_free(number_str);
}

int main() {
    BN_CTX *ctx = BN_CTX_new();
    // task 3.3 - decrypting a message
    char *n_hex = "DCBFFE3E51F62E09CE7032E2677A78946A849DC4CDDE3A4D0CB81629242FB1A5";
    char *d_hex = "74D806F9F3A62BAE331FFE3F0A68AFE35B3D2E4794148AACBC26AA381CD7D30D";
    // python3 -c 'print("A top secret!".encode("utf-8").hex())'
    // 4120746f702073656372657421
    char *C_encoded =
        "8C0F971DF2F3672B28811407E2DABBE1DA0FEBBBDFC7DCB67396567EA1E2493F"; // ciphertext

    BIGNUM *M_decoded = BN_new();
    BIGNUM *n = BN_new();
    BIGNUM *d = BN_new();
    BIGNUM *C = BN_new();

    BN_hex2bn(&n, n_hex);
    BN_hex2bn(&d, d_hex);
    BN_hex2bn(&C, C_encoded);

    BN_mod_exp(M_decoded, C, d, n, ctx);

    printBN2Hex("plaintext (hex):", M_decoded);

    BN_free(n);
    BN_free(d);
    BN_free(C);
    BN_free(M_decoded);
    BN_CTX_free(ctx);

    return 0;
}
