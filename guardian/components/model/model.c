#include "model.h"

/**
 * @brief Generates an election key pair, including the public key, private key, polynomial coefficients, and commitments.
 *
 * This function generates an election key pair based on a specified quorum. It involves creating a polynomial with a degree
 * determined by the quorum size. The coefficients of this polynomial form the basis for the private key, while commitments
 * to these coefficients constitute the public key.
 *
 * @param quorum The number of guardians required to decrypt the election. This determines the degree of the polynomial.
 * @param key_pair A pointer to an `ElectionKeyPair` struct where the generated key pair, polynomial, and related data will be stored.
 *                 The caller is responsible for allocating the `ElectionKeyPair` structure before calling this function.
 *
 * @return 0 on success.
 * @return -1 on failure, typically due to memory allocation issues.
 *
 * @note This function allocates memory for the public key, private key, and polynomial coefficients. It is crucial to free this memory
 *       after use to prevent memory leaks.
 *
 * @code
 * ElectionKeyPair key_pair;
 * int quorum = 10;
 * if (generate_election_key_pair(quorum, &key_pair) == 0) {
 *   // Use the generated key pair
 *   // ...
 *   // Free the allocated memory
 *   free_ElectionKeyPair(&key_pair);
 * } else {
 *   // Handle error
 * }
 * @endcode
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
 * @brief Generates an election partial key backup for sharing between guardians.
 *
 * This function creates a backup of a guardian's partial key, encrypts it using the recipient's public key,
 * and prepares it for secure sharing. The backup includes the encrypted coordinate, sender and receiver identifiers.
 *
 * @param sender   The `ElectionKeyPair` of the guardian sending the backup.
 * @param receiver The `ElectionKeyPair` of the guardian receiving the backup.
 * @param backup   A pointer to an `ElectionPartialKeyPairBackup` struct where the encrypted backup will be stored.
 *                 The caller must allocate memory for this struct before calling the function.
 *
 * @return 0 on success.
 * @return -1 on failure.
 *
 * @note The function uses the receiver's public key to encrypt a coordinate derived from the sender's polynomial.
 *       It's essential to ensure the receiver's public key is valid and trusted.
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
 * @brief Verifies an election partial key backup to confirm it contains a point on the owner's polynomial.
 *
 * This function decrypts the encrypted coordinate from the backup using the receiver's private key and then
 * verifies that the decrypted coordinate corresponds to a point on the sender's polynomial. This ensures the
 * backup is valid and originates from the claimed sender.
 *
 * @param receiver The `ElectionKeyPair` of the guardian receiving and verifying the backup.
 * @param sender The `ElectionKeyPair` of the guardian who sent the backup.
 * @param backup A pointer to the `ElectionPartialKeyPairBackup` struct containing the encrypted backup to be verified.
 * @param verification A pointer to an `ElectionPartialKeyVerification` struct where the verification result will be stored.
 *                     The caller must allocate memory for this struct before calling the function.
 *
 * @return 0 on success.
 *
 * @note The function updates the `verified` field in the `ElectionPartialKeyVerification` struct to indicate whether the
 *       backup is valid.
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
    hash(gid, bid, encryption_seed);
    hashed_elgamal_decrypt(&backup->encrypted_coordinate, receiver->private_key, encryption_seed, coordinate);
    verification->verified = verify_polynomial_coordinate(backup->receiver, &sender->polynomial, coordinate);

    sp_zero(encryption_seed);
    FREE_MP_INT_SIZE(encryption_seed, NULL, DYNAMIC_TYPE_BIGINT);
    FREE_MP_INT_SIZE(coordinate, NULL, DYNAMIC_TYPE_BIGINT);
    FREE_MP_INT_SIZE(gid, NULL, DYNAMIC_TYPE_BIGINT);
    FREE_MP_INT_SIZE(bid, NULL, DYNAMIC_TYPE_BIGINT);
    return 0;
}

/**
 * @brief Combines individual election public keys into a joint public key.
 *
 * This function aggregates the public keys of multiple guardians to form a joint public key, which happens at the end of the key ceremony. 
 *  It also generates a commitment hash of the combined public key.
 *
 * @param guardian   An `ElectionKeyPair` representing the current guardian.
 * @param pubkey_map An array of `ElectionKeyPair` structures, each containing a guardian's public key.
 * @param count      The number of guardians (and thus the number of public keys in `pubkey_map`).
 * @param joint_key  A pointer to an `ElectionJointKey` struct where the resulting joint public key and commitment hash will be stored.
 *                   The caller must allocate memory for this struct before calling the function.
 *
 * @return 0 on success.
 *
 * @note The function computes both the joint public key and its corresponding commitment hash.
 */
int combine_election_public_keys(ElectionKeyPair *guardian, ElectionKeyPair *pubkey_map, size_t count, ElectionJointKey *joint_key) {
    joint_key->joint_key = NULL;
    NEW_MP_INT_SIZE(joint_key->joint_key, 3072, NULL, DYNAMIC_TYPE_BIGINT);
    INIT_MP_INT_SIZE(joint_key->joint_key, 3072);
    joint_key->commitment_hash = NULL;
    NEW_MP_INT_SIZE(joint_key->commitment_hash, 256, NULL, DYNAMIC_TYPE_BIGINT);
    INIT_MP_INT_SIZE(joint_key->commitment_hash, 256);

    DECL_MP_INT_SIZE(jointkey, 3072);
    NEW_MP_INT_SIZE(jointkey, 3072, NULL, DYNAMIC_TYPE_BIGINT);
    INIT_MP_INT_SIZE(jointkey, 3072);
    DECL_MP_INT_SIZE(commitment, 256);
    NEW_MP_INT_SIZE(commitment, 256, NULL, DYNAMIC_TYPE_BIGINT);
    INIT_MP_INT_SIZE(commitment, 256);

    elgamal_combine_public_keys(guardian, pubkey_map, count, jointkey);
    hash_keys(guardian, pubkey_map, count, commitment);
    sp_copy(jointkey, joint_key->joint_key);

    sp_copy(commitment, joint_key->commitment_hash);
    FREE_MP_INT_SIZE(jointkey, NULL, DYNAMIC_TYPE_BIGINT);
    FREE_MP_INT_SIZE(commitment, NULL, DYNAMIC_TYPE_BIGINT);
    return 0;
}

/**
 * @brief Computes a decryption share for a given ciphertext tally using a guardian's private key.
 *
 * Each guardian computes a decryption share for each contest in the ciphertext tally. These shares are later combined
 * to decrypt the tally and reveal the election results.
 *
 * @param guardian     The `ElectionKeyPair` of the guardian computing the decryption share.
 * @param ciphertally  A pointer to the `CiphertextTally` struct containing the encrypted tallies for each contest.
 * @param share        A pointer to a `DecryptionShare` struct where the computed decryption share will be stored.
 *                     The caller must allocate memory for this struct before calling the function.
 *
 * @return 0 on success.
 *
 * @note The function iterates through each contest in the ciphertext tally and computes a decryption share for it.
 */
int compute_decryption_share(ElectionKeyPair *guardian, CiphertextTally *ciphertally, DecryptionShare *share) {
    share->object_id = strdup(ciphertally->object_id);

    memcpy(share->guardian_id, guardian->guardian_id, sizeof(guardian->guardian_id));

    share->public_key = NULL;
    NEW_MP_INT_SIZE(share->public_key, 3072, NULL, DYNAMIC_TYPE_BIGINT);
    INIT_MP_INT_SIZE(share->public_key, 3072);
    sp_copy(guardian->public_key, share->public_key);

    share->num_contest = ciphertally->num_contest;
    share->contests = (CiphertextDecryptionContest*)XMALLOC(ciphertally->num_contest * sizeof(CiphertextDecryptionContest), NULL, DYNAMIC_TYPE_BIGINT);
    for (int i = 0; i < ciphertally->num_contest; i++) {
        compute_decryption_share_for_contest(guardian, &ciphertally->contests[i], ciphertally->base_hash , &share->contests[i]);
    }

    return 0;
}
