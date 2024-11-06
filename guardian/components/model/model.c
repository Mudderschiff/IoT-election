#include "model.h"

/**
 * @brief Generate election partal key backup for sharing
 * @param sender_guardian_id: Owner of election key
 * @param sender_guardian_polynomial: The owner's Election polynomial
 * @param receiver_guardian_public_key: The receiving guardian's public key
 * @return PartialKeyBackup / Encrypted Coordinate
 */
int generate_election_partial_key_backup(int sender_guardian_id, ElectionPolynomial sender_guardian_polynomial, sp_int *receiver_guardian_public_key) {
    DECL_MP_INT_SIZE(coordinate, 256);
    NEW_MP_INT_SIZE(coordinate, 256, NULL, DYNAMIC_TYPE_BIGINT);
    INIT_MP_INT_SIZE(coordinate, 256);
    DECL_MP_INT_SIZE(nonce, 256);
    NEW_MP_INT_SIZE(nonce, 256, NULL, DYNAMIC_TYPE_BIGINT);
    INIT_MP_INT_SIZE(nonce, 256);
    compute_polynomial_coordinate(sender_guardian_id, sender_guardian_polynomial, coordinate);
    rand_q(nonce);
    //hash(receiver_owner_id, receiver_sequence_order, seed);

/*
    seed = get_backup_seed(
        receiver_guardian_public_key.owner_id,
        receiver_guardian_public_key.sequence_order,
    )
    encrypted_coordinate = hashed_elgamal_encrypt(
        coordinate_data.to_bytes(),
        nonce,
        receiver_guardian_public_key.key,
        seed,
    )
    return ElectionPartialKeyBackup(
        sender_guardian_id,
        receiver_guardian_public_key.owner_id,
        receiver_guardian_public_key.sequence_order,
        encrypted_coordinate,
    */
  
    

    //compute_polynomial_coordinate(receiver_sequence_order, sender_guardian_polynomial, coordinate);
    //rand_q(nonce);
    //
    //hashed_elgamal_encrypt(coordinate, nonce, receiver_guardian_public_key.key, seed, encrypted_coordinate);
    //return PartialKeyBackup(sender_guardian_id, receiver_owner_id, receiver_sequence_order, encrypted_coordinate)
    return 0;
}


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
/*
int verify_election_partial_key_backup(int guardian_id, ElectionPartialKeyBackup *backup, ElectionKeyPair *key_pair) {
    return 0;
}
*/


