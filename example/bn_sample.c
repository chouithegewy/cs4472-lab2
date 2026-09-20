/**
 * @file bn_sample.c
 * @brief Worked example of the OpenSSL BIGNUM API: big-integer multiplication
 *        and modular exponentiation.
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
  char *number_str = BN_bn2hex(a);
  printf("%s %s\n", msg, number_str);
  OPENSSL_free(number_str);
}

int main() {
  BN_CTX *ctx = BN_CTX_new();
  BIGNUM *a = BN_new();
  BIGNUM *b = BN_new();
  BIGNUM *n = BN_new();
  BIGNUM *res = BN_new();
  // Initialize a, b, n
  BN_generate_prime_ex(a, NBITS, 1, NULL, NULL, NULL);
  BN_dec2bn(&b, "273489463796838501848592769467194369268");
  BN_rand(n, NBITS, 0, 0);
  // res = a*b
  BN_mul(res, a, b, ctx);
  printBN("a * b = ", res);
  // res = aˆb mod n
  BN_mod_exp(res, a, b, n, ctx);
  printBN("aˆc mod n = ", res);

  return 0;
}
