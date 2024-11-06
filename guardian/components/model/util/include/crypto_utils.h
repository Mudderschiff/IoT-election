#ifndef CRYPTO_UTILS_H
#define CRYPTO_UTILS_H

#include <wolfssl/wolfcrypt/port/Espressif/esp32-crypt.h>
#include <wolfssl/wolfcrypt/wolfmath.h>
#include <wolfssl/ssl.h>
#include "esp_log.h"
#include "esp_random.h"
#include "constants.h"


#define BLOCK_SIZE 32

typedef struct {
    sp_int* pubkey;
    sp_int* commitment;
    sp_int* challenge;
    sp_int* response;
    
} SchnorrProof;

typedef struct {
    sp_int* value;
    sp_int* commitment;
    SchnorrProof proof;
} Coefficient;

typedef struct {
    int num_coefficients;
    Coefficient* coefficients;
} ElectionPolynomial;

// contains also private key. Be careful when sending!
typedef struct {
    int guardian_id;
    sp_int* public_key;
    sp_int* private_key;
    ElectionPolynomial polynomial;
} ElectionKeyPair;
 


/*

typedef struct {
    int guardian_id;
    int designated_id;
    HashedElGamalCiphertext encrypted_coordinate;
} ElectionPartialKeyBackup;

typedef struct {
    int guardian_id;
    int designated_id;
    HashedElGamalCiphertext encrypted_coordinate;
    SchnorrProof proof;
} ElectionPartialKeyVerification;
*/

int compute_polynomial_coordinate(int *exponent_modifier, ElectionPolynomial polynomial, sp_int *coordinate);
int hashed_elgamal_encrypt(sp_int *coordinate, sp_int *nonce, sp_int *public_key, sp_int *seed, sp_int *encrypted_coordinate);
int generate_polynomial(ElectionPolynomial *polynomial);
int powmod(sp_int *g, sp_int *x, sp_int *p, sp_int *y);
int g_pow_p(sp_int *seckey, sp_int *pubkey);
int rand_q(sp_int *result);
int hash(sp_int *a, sp_int *b, sp_int *result);
int kdf(sp_int *key, sp_int *message, sp_int *keystream);
int get_hmac(byte key);
int make_schnorr_proof(sp_int *seckey, sp_int *pubkey, sp_int *nonce, SchnorrProof *proof);

#endif // CRYPTO_UTILS_H