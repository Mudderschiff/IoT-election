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
    uint8_t guardian_id[6];
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
    uint8_t sender[6];
    uint8_t receiver[6];
    HashedElGamalCiphertext encrypted_coordinate;
 } ElectionPartialKeyPairBackup;

 
 typedef struct {
    uint8_t sender[6];
    uint8_t receiver[6];
    uint8_t verifier[6];
    bool verified;
 } ElectionPartialKeyVerification;

 typedef struct {
    sp_int* joint_key;
    sp_int* commitment_hash;
 } ElectionJointKey;

typedef struct {
    char* object_id;
	sp_int* ciphertext_pad;
	sp_int* ciphertext_data;
} CiphertextTallySelection;

typedef struct {
    char* object_id;
    int sequence_order;
    sp_int* description_hash;
    int num_selections;
    CiphertextTallySelection* selections;
} CiphertextTallyContest;

typedef struct{
    char* object_id;
    sp_int* base_hash;
    int num_contest;
    CiphertextTallyContest* contests;
} CiphertextTally;

typedef struct {
    sp_int* pad;
    sp_int* data;
    sp_int* challenge;
    sp_int* response;
} ChaumPedersenProof;

typedef struct {
    char* object_id;
    uint8_t guardian_id[6];
    sp_int* decryption;
    ChaumPedersenProof proof;
} CiphertextDecryptionSelection;

typedef struct{
    char* object_id;
    uint8_t guardian_id[6];
    sp_int *public_key;
    sp_int* description_hash;
    int num_selections;
    CiphertextDecryptionSelection* selections;
} CiphertextDecryptionContest;

typedef struct {
    char* object_id;
    uint8_t guardian_id[6];
    sp_int* public_key;
    int num_contest;
    CiphertextDecryptionContest* contests;
} DecryptionShare;

int elgamal_combine_public_keys(ElectionKeyPair *guardian, ElectionKeyPair *pubkey_map, size_t count, sp_int *key);
int compute_decryption_share_for_contest(ElectionKeyPair *guardian, CiphertextTallyContest *contest, sp_int* base_hash , CiphertextDecryptionContest *dec_contest);

int compute_polynomial_coordinate(uint8_t* exponent_modifier, ElectionPolynomial* polynomial, sp_int *coordinate);
int verify_polynomial_coordinate(uint8_t* exponent_modifier, ElectionPolynomial* polynomial, sp_int *coordinate);

int hashed_elgamal_encrypt(sp_int *message, sp_int *nonce, sp_int *public_key, sp_int *encryption_seed, HashedElGamalCiphertext *encrypted_message);
int hashed_elgamal_decrypt(HashedElGamalCiphertext *encrypted_message, sp_int *secret_key, sp_int *encryption_seed, sp_int *message);

int generate_polynomial(ElectionPolynomial *polynomial);

int hash(sp_int *a, sp_int *b, sp_int *result);
int hash_keys(ElectionKeyPair *guardian, ElectionKeyPair *pubkey_map, size_t count, sp_int *commitment);
int rand_q(sp_int *result);

void print_sp_int(sp_int *num);
void print_byte_array(const byte *array, int size);

#endif // CRYPTO_UTILS_H