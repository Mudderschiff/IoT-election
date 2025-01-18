#include "model.h"
#include "esp_heap_caps.h"

/**
 * @brief Generates election key pair, proof, and polynomial
 * @param quorum: The number of guardians required to decrypt the election
 * @param key_pair: The election key pair
 * @return 0 on success, -1 on failure
 */
int generate_election_key_pair(int quorum, ElectionKeyPair *key_pair) {
    key_pair->public_key = NULL;
    NEW_MP_INT_SIZE(key_pair->public_key, 3072, NULL, DYNAMIC_TYPE_BIGINT);
    INIT_MP_INT_SIZE(key_pair->public_key, 3072);

    key_pair->private_key = NULL;
    NEW_MP_INT_SIZE(key_pair->private_key, 256, NULL, DYNAMIC_TYPE_BIGINT);
    INIT_MP_INT_SIZE(key_pair->private_key, 256);
    
    key_pair->polynomial.num_coefficients = quorum;
    key_pair->polynomial.coefficients = (Coefficient*)XMALLOC(quorum * sizeof(Coefficient), NULL, DYNAMIC_TYPE_BIGINT);
    if (key_pair->polynomial.coefficients == NULL) {
        ESP_LOGE("Generate Election Key Pair", "Failed to allocate memory for coefficients");
        return -1;
    }
    generate_polynomial(&key_pair->polynomial);
    sp_copy(key_pair->polynomial.coefficients[0].value, key_pair->private_key);
    sp_copy(key_pair->polynomial.coefficients[0].commitment, key_pair->public_key);
    return 0;
}

/**
 * @brief Generate election partal key backup for sharing
 * @param sender_guardian_id: Owner of election key
 * @param sender_guardian_polynomial: The owner's Election polynomial
 * @param receiver_guardian_public_key: The receiving guardian's public key
 * @return PartialKeyBackup / Encrypted Coordinate
 */
int generate_election_partial_key_backup(ElectionKeyPair *sender, ElectionKeyPair *receiver, ElectionPartialKeyPairBackup *backup) {
    DECL_MP_INT_SIZE(coordinate, 256);
    NEW_MP_INT_SIZE(coordinate, 256, NULL, DYNAMIC_TYPE_BIGINT);
    INIT_MP_INT_SIZE(coordinate, 256);

    DECL_MP_INT_SIZE(nonce, 256);
    NEW_MP_INT_SIZE(nonce, 256, NULL, DYNAMIC_TYPE_BIGINT);
    INIT_MP_INT_SIZE(nonce, 256);

    DECL_MP_INT_SIZE(seed, 256);
    NEW_MP_INT_SIZE(seed, 256, NULL, DYNAMIC_TYPE_BIGINT);
    INIT_MP_INT_SIZE(seed, 256);

    DECL_MP_INT_SIZE(id, 48);
    NEW_MP_INT_SIZE(id, 48, NULL, DYNAMIC_TYPE_BIGINT);
    INIT_MP_INT_SIZE(id, 48);
    sp_read_unsigned_bin(id, receiver->guardian_id, sizeof(receiver->guardian_id));

    memcpy(backup->sender, sender->guardian_id, sizeof(sender->guardian_id));
    memcpy(backup->receiver, receiver->guardian_id, sizeof(receiver->guardian_id));

    backup->encrypted_coordinate.pad = NULL;
    NEW_MP_INT_SIZE(backup->encrypted_coordinate.pad, 3072, NULL, DYNAMIC_TYPE_BIGINT);
    INIT_MP_INT_SIZE(backup->encrypted_coordinate.pad, 3072);

    backup->encrypted_coordinate.data = NULL;
    NEW_MP_INT_SIZE(backup->encrypted_coordinate.data, 256, NULL, DYNAMIC_TYPE_BIGINT);
    INIT_MP_INT_SIZE(backup->encrypted_coordinate.data, 256);

    backup->encrypted_coordinate.mac = NULL;
    NEW_MP_INT_SIZE(backup->encrypted_coordinate.mac, 256, NULL, DYNAMIC_TYPE_BIGINT);
    INIT_MP_INT_SIZE(backup->encrypted_coordinate.mac, 256);

    compute_polynomial_coordinate(receiver->guardian_id, &sender->polynomial, coordinate);
    rand_q(nonce);
    hash(id, id, seed);
    hashed_elgamal_encrypt(coordinate, nonce, receiver->public_key, seed, &backup->encrypted_coordinate);
    sp_zero(nonce);
    sp_zero(seed);
    FREE_MP_INT_SIZE(coordinate, NULL, DYNAMIC_TYPE_BIGINT);
    FREE_MP_INT_SIZE(nonce, NULL, DYNAMIC_TYPE_BIGINT);
    FREE_MP_INT_SIZE(seed, NULL, DYNAMIC_TYPE_BIGINT);
    FREE_MP_INT_SIZE(id, NULL, DYNAMIC_TYPE_BIGINT);
    return 0;
}

/**
 * @brief Verify election partial key backup contain point on owners polynomial
 * @param guardian_id: Receiving guardian's identifier
 * @param sender_guardian_backup: Sender guardian's election partial key backup
 * @param sender_guardian_public_key: Sender guardian's election public key
 * @param receiver_guardian_keys: Receiving guardian's key pair
 */
int verify_election_partial_key_backup(ElectionKeyPair *receiver, ElectionKeyPair *sender, ElectionPartialKeyPairBackup *backup, ElectionPartialKeyVerification *verification) {
    DECL_MP_INT_SIZE(encryption_seed, 256);
    NEW_MP_INT_SIZE(encryption_seed, 256, NULL, DYNAMIC_TYPE_BIGINT);
    INIT_MP_INT_SIZE(encryption_seed, 256);

    DECL_MP_INT_SIZE(coordinate, 3072);
    NEW_MP_INT_SIZE(coordinate, 3072, NULL, DYNAMIC_TYPE_BIGINT);
    INIT_MP_INT_SIZE(coordinate, 3072);

    DECL_MP_INT_SIZE(gid, 48);
    NEW_MP_INT_SIZE(gid, 48, NULL, DYNAMIC_TYPE_BIGINT);
    INIT_MP_INT_SIZE(gid, 48);
    DECL_MP_INT_SIZE(bid, 48);
    NEW_MP_INT_SIZE(bid, 48, NULL, DYNAMIC_TYPE_BIGINT);
    INIT_MP_INT_SIZE(bid, 48);
    sp_read_unsigned_bin(gid, receiver->guardian_id, sizeof(receiver->guardian_id));
    sp_read_unsigned_bin(bid, backup->receiver, sizeof(backup->receiver));
    
    memcpy(verification->sender, backup->sender, sizeof(backup->sender));
    memcpy(verification->receiver, backup->receiver, sizeof(backup->receiver));
    memcpy(verification->verifier, receiver->guardian_id, sizeof(receiver->guardian_id));
    verification->verified = false;
    //get_backup_seed()
    hash(gid, bid, encryption_seed);
    // decrypt encrypted_coordinate
    hashed_elgamal_decrypt(&backup->encrypted_coordinate, receiver->private_key, encryption_seed, coordinate);
    verification->verified = verify_polynomial_coordinate(backup->receiver, &sender->polynomial, coordinate);

    sp_zero(encryption_seed);
    FREE_MP_INT_SIZE(encryption_seed, NULL, DYNAMIC_TYPE_BIGINT);
    FREE_MP_INT_SIZE(coordinate, NULL, DYNAMIC_TYPE_BIGINT);
    FREE_MP_INT_SIZE(gid, NULL, DYNAMIC_TYPE_BIGINT);
    FREE_MP_INT_SIZE(bid, NULL, DYNAMIC_TYPE_BIGINT);
    return 0;
}

int combine_election_public_keys(ElectionKeyPair *guardian, ElectionKeyPair *pubkey_map, size_t count, ElectionJointKey *joint_key) {
    joint_key->joint_key = NULL;
    NEW_MP_INT_SIZE(joint_key->joint_key, 3072, NULL, DYNAMIC_TYPE_BIGINT);
    INIT_MP_INT_SIZE(joint_key->joint_key, 3072);
    
    joint_key->commitment_hash = NULL;
    NEW_MP_INT_SIZE(joint_key->commitment_hash, 256, NULL, DYNAMIC_TYPE_BIGINT);
    INIT_MP_INT_SIZE(joint_key->commitment_hash, 256);
    
    ElectionKeyPair *extend = (ElectionKeyPair*)XMALLOC((count + 1) * sizeof(ElectionKeyPair), NULL, DYNAMIC_TYPE_BIGINT);
    memcpy(extend, pubkey_map, count * sizeof(ElectionKeyPair));
    extend[count] = *guardian;

    elgamal_combine_public_keys(extend, count + 1, joint_key);
    hash_keys(extend, count + 1, joint_key);
    return 0;
}

/*
int compute_decryption_share(ElectionKeyPair *guardian, CiphertextTallySelections *selections, DecryptionShare *share) {
    share->public_key = NULL;
    NEW_MP_INT_SIZE(share->public_key, 3072, NULL, DYNAMIC_TYPE_BIGINT);
    INIT_MP_INT_SIZE(share->public_key, 3072);
    sp_copy(share->public_key, guardian->private_key);
    share->guardian_id = NULL;
    NEW_MP_INT_SIZE(share->guardian_id, 48, NULL, DYNAMIC_TYPE_BIGINT);
    INIT_MP_INT_SIZE(share->guardian_id, 48);
    sp_copy(share->guardian_id, guardian->guardian_id);

    //CiphertextDecryptionContest *contests = (CiphertextDecryptionContest*)XMALLOC(selections->num_selections * sizeof(CiphertextDecryptionContest), NULL, DYNAMIC_TYPE_BIGINT);


    return 0;
}
*/
