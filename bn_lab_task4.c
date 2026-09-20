/**
 * @file bn_lab_task4.c
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
    // task 3.4 - digital signing
    char *n_hex = "DCBFFE3E51F62E09CE7032E2677A78946A849DC4CDDE3A4D0CB81629242FB1A5";
    char *e_hex = "010001"; //  (this hex value equals to decimal 65537)
    char *d_hex = "74D806F9F3A62BAE331FFE3F0A68AFE35B3D2E4794148AACBC26AA381CD7D30D";
    //char *M_str = "I owe you $2000."; // plaintext
    // python3 -c 'print("I owe you $2000.".encode("utf-8").hex())'
    //char *M_hex = "49206f776520796f752024323030302e";
    // python3 -c 'print("I owe you $1500.".encode("utf-8").hex())'
    char *M_hex = "49206f776520796f752024313530302e";

    BIGNUM *M = BN_new();
    BIGNUM *n = BN_new();
    BIGNUM *e = BN_new();
    BIGNUM *d = BN_new();
    BIGNUM *C = BN_new();

    BN_hex2bn(&n, n_hex);
    BN_hex2bn(&d, d_hex);
    BN_hex2bn(&e, e_hex);
    BN_hex2bn(&M, M_hex);

    // to digitally sign the message directly (and not a hash), we must encrypt the message with our private key
    // anyone can verify we are the holder of the public key's private key since decrypting the signed message with the public key is verification
    BN_mod_exp(C, M, d, n, ctx);

    printBNStr("ciphertext (hex):", C);

    // verifying answer
    // so C^e mod n should = M
    // since we used our own private key to encrypt the message, our own public key (which anyone can see) can verify we authored the message
    BIGNUM *res = BN_new();
    BN_mod_exp(res, C, e, n, ctx);
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
