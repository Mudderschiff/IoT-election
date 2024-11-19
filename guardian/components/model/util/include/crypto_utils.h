#ifndef CRYPTO_UTILS_H
#define CRYPTO_UTILS_H

#include <wolfssl/wolfcrypt/port/Espressif/esp32-crypt.h>
#include <wolfssl/wolfcrypt/wolfmath.h>
#include <wolfssl/ssl.h>
#include "esp_log.h"
#include "esp_random.h"
#include "constants.h"



#define BLOCK_SIZE 32
#define MODIFIED_CHUNK_SIZE (BLOCK_SIZE + 8)

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
 
 typedef struct {
    sp_int* pad;
    sp_int* data;
    sp_int* mac;
} HashedElGamalCiphertext;

 typedef struct {
    int sender;
    int receiver;
    HashedElGamalCiphertext encrypted_coordinate;
 } ElectionPartialKeyPairBackup;

 
 typedef struct {
    int sender;
    int receiver;
    int verifier;
    bool verified;
 } ElectionPartialKeyVerification;





int compute_polynomial_coordinate(int exponent_modifier, ElectionPolynomial polynomial, sp_int *coordinate);
int verify_polynomial_coordinate(int exponent_modifier, ElectionPolynomial polynomial, sp_int *coordinate);
int hashed_elgamal_encrypt(sp_int *message, sp_int *nonce, sp_int *public_key, sp_int *encryption_seed, HashedElGamalCiphertext *encrypted_message);
int hashed_elgamal_decrypt(HashedElGamalCiphertext *encrypted_message, sp_int *secret_key, sp_int *encryption_seed, sp_int *message);
int generate_polynomial(ElectionPolynomial *polynomial);
int powmod(sp_int *g, sp_int *x, sp_int *p, sp_int *y);
int g_pow_p(sp_int *seckey, sp_int *pubkey);
int rand_q(sp_int *result);
int hash(sp_int *a, sp_int *b, sp_int *result);
int get_hmac(unsigned char *key, unsigned char *in, unsigned char *out);
int kdf_xor(sp_int *key, sp_int *salt, sp_int *message, sp_int *encrypted_message);
int make_schnorr_proof(sp_int *seckey, sp_int *pubkey, sp_int *nonce, SchnorrProof *proof);
void print_sp_int(sp_int *num);
void print_byte_array(const byte *array, int size);
void int_to_bytes(int value, unsigned char *bytes);

#endif // CRYPTO_UTILS_H