#include "model.h"


/**
 * @brief Generates election key pair, proof, and polynomial
 * @param quorum: The number of guardians required to decrypt the election
 * @param key_pair: The election key pair
 * @return 0 on success, -1 on failure
 */
int generate_election_key_pair(int quorum, ElectionKeyPair *key_pair) {
    key_pair->private_key = (sp_int*)XMALLOC(MP_INT_SIZEOF(MP_BITS_CNT(256)), NULL, DYNAMIC_TYPE_BIGINT);
    key_pair->public_key = (sp_int*)XMALLOC(MP_INT_SIZEOF(MP_BITS_CNT(3072)), NULL, DYNAMIC_TYPE_BIGINT);
    if (key_pair->private_key != NULL) {
        XMEMSET(key_pair->private_key, 0, MP_INT_SIZEOF(MP_BITS_CNT(256)));
        mp_init_size(key_pair->private_key, MP_BITS_CNT(256));
    }
    if (key_pair->public_key != NULL) {
        XMEMSET(key_pair->public_key, 0, MP_INT_SIZEOF(MP_BITS_CNT(3072)));
        mp_init_size(key_pair->public_key, MP_BITS_CNT(3072));
    }
    ElectionPolynomial polynomial;
    polynomial.num_coefficients = quorum;
    polynomial.coefficients = (Coefficient*)XMALLOC(quorum * sizeof(Coefficient), NULL, DYNAMIC_TYPE_BIGINT);
    if (polynomial.coefficients == NULL) {
        ESP_LOGE("Generate Election Key Pair", "Failed to allocate memory for coefficients");
        return -1;
    }
    generate_polynomial(&polynomial);
    sp_copy(polynomial.coefficients[0].value, key_pair->private_key);
    sp_copy(polynomial.coefficients[0].commitment, key_pair->public_key);
    return 0;
}

/**
 * @brief Generate election partal key backup for sharing
 * @param sender_guardian_id: Owner of election key
 * @param sender_guardian_polynomial: The owner's Election polynomial
 * @param receiver_guardian_public_key: The receiving guardian's public key
 * @return PartialKeyBackup / Encrypted Coordinate
 */
int generate_election_partial_key_backup(int sender_guardian_id, int designated_id, ElectionPolynomial *sender_guardian_polynomial, sp_int *receiver_guardian_public_key, ElectionPartialKeyPairBackup *backup) {
    backup->guardian_id = sender_guardian_id;
    backup->designated_id = designated_id;
    backup->encrypted_coordinate = (sp_int*)XMALLOC(MP_INT_SIZEOF(MP_BITS_CNT(3072)), NULL, DYNAMIC_TYPE_BIGINT);
    if (backup->encrypted_coordinate != NULL) {
        XMEMSET(backup->encrypted_coordinate, 0, MP_INT_SIZEOF(MP_BITS_CNT(3072)));
        mp_init_size(backup->encrypted_coordinate, MP_BITS_CNT(3072));
    }
    DECL_MP_INT_SIZE(coordinate, 256);
    NEW_MP_INT_SIZE(coordinate, 256, NULL, DYNAMIC_TYPE_BIGINT);
    INIT_MP_INT_SIZE(coordinate, 256);
    DECL_MP_INT_SIZE(nonce, 256);
    NEW_MP_INT_SIZE(nonce, 256, NULL, DYNAMIC_TYPE_BIGINT);
    INIT_MP_INT_SIZE(nonce, 256);
    DECL_MP_INT_SIZE(seed, 256);
    NEW_MP_INT_SIZE(seed, 256, NULL, DYNAMIC_TYPE_BIGINT);
    INIT_MP_INT_SIZE(seed, 256);

    compute_polynomial_coordinate(sender_guardian_id, sender_guardian_polynomial, coordinate);
    rand_q(nonce);
    hash(sender_guardian_id, sender_guardian_id, seed);
    hashed_elgamal_encrypt(coordinate, nonce, receiver_guardian_public_key, seed, backup->encrypted_coordinate);
    
    sp_zero(coordinate);
    sp_zero(nonce);
    sp_zero(seed);
    FREE_MP_INT_SIZE(coordinate, NULL, DYNAMIC_TYPE_BIGINT);
    FREE_MP_INT_SIZE(nonce, NULL, DYNAMIC_TYPE_BIGINT);
    FREE_MP_INT_SIZE(seed, NULL, DYNAMIC_TYPE_BIGINT);
    return 0;
}

/**
 * @brief Verify election partial key backup contain point on owners polynomial
 * @param guardian_id: Receiving guardian's identifier
 * @param sender_guardian_backup: Sender guardian's election partial key backup
 * @param sender_guardian_public_key: Sender guardian's election public key
 * @param receiver_guardian_keys: Receiving guardian's key pair
 */
int verify_election_partial_key_backup(ElectionKeyPair *guardian, ElectionKeyPair *designated, ElectionPartialKeyPairBackup *backup, ElectionKeyPair *key_pair) {
    DECL_MP_INT_SIZE(encryption_seed, 256);
    NEW_MP_INT_SIZE(encryption_seed, 256, NULL, DYNAMIC_TYPE_BIGINT);
    INIT_MP_INT_SIZE(encryption_seed, 256);
    DECL_MP_INT_SIZE(coordinate, 3072);
    NEW_MP_INT_SIZE(coordinate, 3072, NULL, DYNAMIC_TYPE_BIGINT);
    INIT_MP_INT_SIZE(coordinate, 3072);

    hash(guardian->guardian_id, designated->guardian_id, encryption_seed);
    //own_keypair->private_key;
    hashed_elgamal_decrypt(guardian->private_key, encryption_seed, backup->encrypted_coordinate, coordinate);

    ElectionPartialKeyVerification verification;
    verification.guardian_id = guardian->guardian_id;
    verification.designated_id = designated->guardian_id;
    verification.verified_id = designated->guardian_id;
    verification.verified = false;
    verify_polynomial_coordinate(designated->guardian_id, coordinate, designated->polynomial, verification.verified);
    
    sp_zero(encryption_seed);
    FREE_MP_INT_SIZE(encryption_seed, NULL, DYNAMIC_TYPE_BIGINT);
    return 0;
}



