/**
 * @file bn_lab.c
 * @brief CS4472 Lab 2 - deriving an RSA private key with the OpenSSL BIGNUM API.
 */
#include <assert.h>
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

void printRes(BIGNUM *e, BIGNUM *d, BIGNUM *n) {
    char *e_str = BN_bn2dec(e);
    char *d_str = BN_bn2dec(d);
    char *totient_n_str = BN_bn2dec(n);
    printf("pub: (%s, %s)\npriv: (%s, %s)\n", e_str, totient_n_str, d_str, totient_n_str);
    OPENSSL_free(e_str);
    OPENSSL_free(d_str);
    OPENSSL_free(totient_n_str);
}

int main() {
    BN_CTX *ctx = BN_CTX_new();
    // task 3.1 - deriving the private key d
    // p = F7E75FDC469067FFDC4E847C51F452DF
    // q = E85CED54AF57E53E092113E62F436F4F
    // e = 0D88C3

    BIGNUM *p = BN_new();
    BIGNUM *q = BN_new();
    BIGNUM *e = BN_new();
    BIGNUM *n = BN_new();
    BIGNUM *totient_n = BN_new();
    BIGNUM *d = BN_new();

    BN_hex2bn(&p, "F7E75FDC469067FFDC4E847C51F452DF");
    BN_hex2bn(&q, "E85CED54AF57E53E092113E62F436F4F");
    BN_hex2bn(&e, "0D88C3");
    BN_mul(n, p, q, ctx);
    // printBN("p = ", p);
    // printBN("q = ", q);
    BN_sub_word(p, 1);
    BN_sub_word(q, 1);
    // printBN("p - 1 = ", p);
    // printBN("q - 1 = ", q);
    BN_mul(totient_n, p, q, ctx);
    // printBN("(p - 1) * (q - 1) = ", totient_n);

    //// gcd(e, totient(n)) == 1
    BIGNUM *is_e_and_totient_n_coprime = BN_new();
    BN_gcd(is_e_and_totient_n_coprime, e, totient_n, ctx);
    assert(BN_is_one(is_e_and_totient_n_coprime));

    BN_mod_inverse(d, e, totient_n, ctx);
    // printBN("eˆ-1 mod totient_n = ", d);
    //  d 24212225287904763939160097464943268930139828978795606022583874367720623008491
    // printBN("calculated d = ", d);
    //  check res
    //  d = e inverse mod totient n
    //  aka e * d congruent 1 mod totient n
    BIGNUM *res = BN_new();
    BN_mod_mul(res, e, d, totient_n, ctx);
    if (BN_is_one(res)) {
        // printBN("private key d:", d);
        // printBN("public key e:", e);
        // printBN("totient n (p - 1)(q - 1):", totient_n);
        printRes(e, d, n);
    } else {
        printf("not correct");
    }

    return 0;
}
