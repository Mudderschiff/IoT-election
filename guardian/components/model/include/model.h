#ifndef MODEL_H
#define MODEL_H

#include <wolfssl/wolfcrypt/port/Espressif/esp32-crypt.h>
#include <wolfssl/wolfcrypt/wolfmath.h>
#include <wolfssl/ssl.h>
#include "esp_log.h"
#include "esp_random.h"
#include "model.h"

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

typedef struct {
    sp_int* secret_key;
    sp_int* public_key;
} ElGamalKeyPair;


int powmod(sp_int *g, sp_int *x, sp_int *p, sp_int *y);
void print_sp_int(sp_int *num);
int g_pow_p(sp_int *seckey, sp_int *pubkey);
int rand_q(sp_int *result);
int hash(sp_int *a, sp_int *b, sp_int *result);
int make_schnorr_proof(sp_int *seckey, sp_int *pubkey, sp_int *nonce, SchnorrProof *proof);
int generate_election_partial_key_backup();
int hashed_elgamal_encrypt(sp_int *coordinate, sp_int *nonce, sp_int *public_key, sp_int *seed, sp_int *encrypted_coordinate);
int generate_election_partial_key_backup();
int kdf(sp_int *key, sp_int *message, sp_int *keystream);
int get_hmac(byte key);
int generate_polynomial(ElectionPolynomial *polynomial);
int generate_election_key_pair(int quorum, ElGamalKeyPair *key_pair);
//int compute_polynomial_coordinate(sp_int *exponent_modifier, Polynomial polynomial, sp_int *coordinate);
void int_to_bytes(int value, uint8_t *bytes);

#endif // MOD_MATH_H