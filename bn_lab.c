/**
 * @file bn_lab.c
 * @brief CS4472 Lab 2 - deriving an RSA private key with the OpenSSL BIGNUM API.
 */
#include <openssl/bn.h>
#include <stdio.h>

#define NBITS 256

/**
 * @brief Print a BIGNUM to stdout as "<msg> <hex digits>".
 *
 * @param msg Label printed before the number. Not modified.
 * @param a   Value to print. Must be non-NULL and initialized by BN_new().
 *
 * @note BN_bn2hex() allocates the string, so it is released with
 *       OPENSSL_free(). Swap it for BN_bn2dec() to print in decimal.
 *
 * @see BN_bn2bin(3ssl)
 */
void printBN(char *msg, BIGNUM *a) {
    char *number_str = BN_bn2dec(a);
    printf("%s %s\n", msg, number_str);
    OPENSSL_free(number_str);
}

int main() {
    BN_CTX *ctx = BN_CTX_new();
    // constants from lab pdf:
    // "A top secret".encode('utf-8').hex() == 4120746f7020736563726574
    // p * q
    // n = DCBFFE3E51F62E09CE7032E2677A78946A849DC4CDDE3A4D0CB81629242FB1A5
    // e = 010001 (this hex value equals to decimal 65537)

    // plaintext M
    // M = A top secret!

    // private key
    // d = 74D806F9F3A62BAE331FFE3F0A68AFE35B3D2E4794148AACBC26AA381CD7D30D

    // ciphertext C
    // C = 8C0F971DF2F3672B28811407E2DABBE1DA0FEBBBDFC7DCB67396567EA1E2493F
    //
    //
    //
    //
    // task 3.1 - deriving the private key d
    // p = F7E75FDC469067FFDC4E847C51F452DF
    // q = E85CED54AF57E53E092113E62F436F4F
    // chosen e (co-prime to n)
    // e = 0D88C3

    BIGNUM *p = BN_new();
    BIGNUM *q = BN_new();
    BIGNUM *e = BN_new();
    BIGNUM *n = BN_new();
    BIGNUM *d = BN_new();

    BN_hex2bn(&p, "F7E75FDC469067FFDC4E847C51F452DF");
    BN_hex2bn(&q, "E85CED54AF57E53E092113E62F436F4F");
    BN_hex2bn(&e, "0D88C3");

    printBN("p = ", p);
    printBN("q = ", q);
    BN_sub_word(p, 1);
    BN_sub_word(q, 1);
    printBN("p - 1 = ", p);
    printBN("q - 1 = ", q);
    BN_mul(n, p, q, ctx);
    printBN("p * q = ", n);
    // res = aˆb mod n
    BN_mod_inverse(d, e, n, ctx);
    printBN("eˆ-1 mod n = ", d);

    return 0;
}
