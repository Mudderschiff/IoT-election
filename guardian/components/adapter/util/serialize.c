#include "serialize.h"


/**
 * @brief Serialize an ElectionKeyPair struct into a byte array
 * 
 * This function takes an ElectionKeyPair struct and serializes it into a byte array
 * using Protocol Buffers. The serialized data includes the guardian ID, public key,
 * and the election polynomial with its coefficients and Schnorr proofs.
 *
 * @param key_pair Pointer to the ElectionKeyPair object to serialize.
 * @param len Pointer to an unsigned integer that will store the length of the serialized byte array.
 * @return A pointer to the serialized byte array. The caller is responsible for freeing the allocated memory.
 */
uint8_t* serialize_election_key_pair(ElectionKeyPair* key_pair, unsigned* len) {
    ElectionKeyPairProto proto = ELECTION_KEY_PAIR_PROTO__INIT;
    ElectionPolynomialProto polynomial = ELECTION_POLYNOMIAL_PROTO__INIT;
    CoefficientProto **coeff;
    
    proto.guardian_id.len = sizeof(key_pair->guardian_id);
    proto.guardian_id.data = key_pair->guardian_id;
    proto.public_key.len = sp_unsigned_bin_size(key_pair->public_key);
    proto.public_key.data = (uint8_t*)malloc(proto.public_key.len);
    sp_to_unsigned_bin(key_pair->public_key, proto.public_key.data);

    coeff = (CoefficientProto**)malloc(sizeof(CoefficientProto*) * key_pair->polynomial.num_coefficients);

    for(int i = 0; i < key_pair->polynomial.num_coefficients; i++) {
        coeff[i] = (CoefficientProto*)malloc(sizeof(CoefficientProto));
        coefficient_proto__init(coeff[i]);
        coeff[i]->value.len = sp_unsigned_bin_size(key_pair->polynomial.coefficients[i].value);
        coeff[i]->value.data = (uint8_t*)malloc(coeff[i]->value.len);
        sp_to_unsigned_bin(key_pair->polynomial.coefficients[i].value, coeff[i]->value.data);

        coeff[i]->commitment.len = sp_unsigned_bin_size(key_pair->polynomial.coefficients[i].commitment);
        coeff[i]->commitment.data = (uint8_t*)malloc(coeff[i]->commitment.len);
        sp_to_unsigned_bin(key_pair->polynomial.coefficients[i].commitment, coeff[i]->commitment.data);

        coeff[i]->proof = (SchnorrProofProto*)malloc(sizeof(SchnorrProofProto));
        schnorr_proof_proto__init(coeff[i]->proof);

        coeff[i]->proof->pubkey.len = sp_unsigned_bin_size(key_pair->polynomial.coefficients[i].proof.pubkey);
        coeff[i]->proof->pubkey.data = (uint8_t*)malloc(coeff[i]->proof->pubkey.len);
        sp_to_unsigned_bin(key_pair->polynomial.coefficients[i].proof.pubkey, coeff[i]->proof->pubkey.data);

        coeff[i]->proof->commitment.len = sp_unsigned_bin_size(key_pair->polynomial.coefficients[i].proof.commitment);
        coeff[i]->proof->commitment.data = (uint8_t*)malloc(coeff[i]->proof->commitment.len);
        sp_to_unsigned_bin(key_pair->polynomial.coefficients[i].proof.commitment, coeff[i]->proof->commitment.data);

        coeff[i]->proof->challenge.len = sp_unsigned_bin_size(key_pair->polynomial.coefficients[i].proof.challenge);
        coeff[i]->proof->challenge.data = (uint8_t*)malloc(coeff[i]->proof->challenge.len);
        sp_to_unsigned_bin(key_pair->polynomial.coefficients[i].proof.challenge, coeff[i]->proof->challenge.data);

        coeff[i]->proof->response.len = sp_unsigned_bin_size(key_pair->polynomial.coefficients[i].proof.response);
        coeff[i]->proof->response.data = (uint8_t*)malloc(coeff[i]->proof->response.len);
        sp_to_unsigned_bin(key_pair->polynomial.coefficients[i].proof.response, coeff[i]->proof->response.data);
    }
    polynomial.n_coefficients = key_pair->polynomial.num_coefficients;
    polynomial.num_coefficients = key_pair->polynomial.num_coefficients;

    polynomial.coefficients = coeff;
    proto.polynomial = &polynomial;

    *len = election_key_pair_proto__get_packed_size(&proto);
    uint8_t* buffer = (uint8_t *)calloc(*len, sizeof(char));
    election_key_pair_proto__pack(&proto, buffer);
    return buffer;
}

/**
 * @brief Deserializes a SchnorrProofProto object into a SchnorrProof struct.
 *
 * This function takes a SchnorrProofProto object (protobuf representation) and populates
 * a SchnorrProof struct with the deserialized data. It allocates memory for the big integer
 * fields within the SchnorrProof struct.
 *
 * @param proto Pointer to the SchnorrProofProto object to deserialize.
 * @param proof Pointer to the SchnorrProof struct to populate with the deserialized data.
 * @return 0 on success, or an error code on failure.
 */
static int deserialize_schnorr_proof(SchnorrProofProto* proto, SchnorrProof* proof) {
    int bit_len;
    bit_len = (proto->pubkey.len) * 8;
    proof->pubkey = NULL;
    proof->pubkey = (sp_int*)XMALLOC(MP_INT_SIZEOF(MP_BITS_CNT(bit_len)), NULL, DYNAMIC_TYPE_BIGINT);
    if(proof->pubkey != NULL) {
        XMEMSET(proof->pubkey, 0, MP_INT_SIZEOF(MP_BITS_CNT(bit_len)));
        sp_init_size(proof->pubkey, MP_BITS_CNT(bit_len));
    }
    sp_read_unsigned_bin(proof->pubkey, proto->pubkey.data, proto->pubkey.len); 

    bit_len = (proto->commitment.len) * 8;
    proof->commitment = NULL;
    proof->commitment = (sp_int*)XMALLOC(MP_INT_SIZEOF(MP_BITS_CNT(bit_len)), NULL, DYNAMIC_TYPE_BIGINT);
    if(proof->commitment != NULL) {
        XMEMSET(proof->commitment, 0, MP_INT_SIZEOF(MP_BITS_CNT(bit_len)));
        sp_init_size(proof->commitment, MP_BITS_CNT(bit_len));
    }
    sp_read_unsigned_bin(proof->commitment, proto->commitment.data, proto->commitment.len);

    bit_len = (proto->challenge.len) * 8;
    proof->challenge = NULL;
    proof->challenge = (sp_int*)XMALLOC(MP_INT_SIZEOF(MP_BITS_CNT(bit_len)), NULL, DYNAMIC_TYPE_BIGINT);
    if(proof->challenge != NULL) {
        XMEMSET(proof->challenge, 0, MP_INT_SIZEOF(MP_BITS_CNT(bit_len)));
        sp_init_size(proof->challenge, MP_BITS_CNT(bit_len));
    }
    sp_read_unsigned_bin(proof->challenge, proto->challenge.data, proto->challenge.len);

    bit_len = (proto->response.len) * 8;
    proof->response = NULL;
    proof->response = (sp_int*)XMALLOC(MP_INT_SIZEOF(MP_BITS_CNT(bit_len)), NULL, DYNAMIC_TYPE_BIGINT);
    if(proof->response != NULL) {
        XMEMSET(proof->response, 0, MP_INT_SIZEOF(MP_BITS_CNT(bit_len)));
        sp_init_size(proof->response, MP_BITS_CNT(bit_len));
    }
    sp_read_unsigned_bin(proof->response, proto->response.data, proto->response.len);
    return 0;
}

/**
 * @brief Deserializes an ElectionPolynomialProto object into an ElectionPolynomial struct.
 *
 * This function takes an ElectionPolynomialProto object (protobuf representation) and populates
 * an ElectionPolynomial struct with the deserialized data. It allocates memory for the coefficients
 * and their associated data, including Schnorr proofs.
 *
 * @param poly Pointer to the ElectionPolynomialProto object to deserialize.
 * @param polynomial Pointer to the ElectionPolynomial struct to populate with the deserialized data.
 * @return 0 on success, or an error code on failure.
 */
static int deserialize_election_polynomial(ElectionPolynomialProto* poly, ElectionPolynomial* polynomial) {
    polynomial->num_coefficients = poly->num_coefficients;
    int bit_len;
    polynomial->coefficients = (Coefficient*)malloc(sizeof(Coefficient) * polynomial->num_coefficients);
    for(int i = 0; i < polynomial->num_coefficients; i++) {
        bit_len = (poly->coefficients[i]->value.len) * 8;
        polynomial->coefficients[i].value = NULL;
        polynomial->coefficients[i].value = (sp_int*)XMALLOC(MP_INT_SIZEOF(MP_BITS_CNT(bit_len)), NULL, DYNAMIC_TYPE_BIGINT);
        if(polynomial->coefficients[i].value != NULL) {
            XMEMSET(polynomial->coefficients[i].value, 0, MP_INT_SIZEOF(MP_BITS_CNT(bit_len)));
            sp_init_size(polynomial->coefficients[i].value, MP_BITS_CNT(bit_len));
        }
        sp_read_unsigned_bin(polynomial->coefficients[i].value, poly->coefficients[i]->value.data, poly->coefficients[i]->value.len);

        bit_len = (poly->coefficients[i]->commitment.len) * 8;
        polynomial->coefficients[i].commitment = NULL;
        polynomial->coefficients[i].commitment = (sp_int*)XMALLOC(MP_INT_SIZEOF(MP_BITS_CNT(bit_len)), NULL, DYNAMIC_TYPE_BIGINT);
        if(polynomial->coefficients[i].commitment != NULL) {
            XMEMSET(polynomial->coefficients[i].commitment, 0, MP_INT_SIZEOF(MP_BITS_CNT(bit_len)));
            sp_init_size(polynomial->coefficients[i].commitment, MP_BITS_CNT(bit_len));
        }
        sp_read_unsigned_bin(polynomial->coefficients[i].commitment, poly->coefficients[i]->commitment.data, poly->coefficients[i]->commitment.len);

        deserialize_schnorr_proof(poly->coefficients[i]->proof, &polynomial->coefficients[i].proof);
    }
    return 0;
}
/**
 * @brief Deserializes a byte array into an ElectionKeyPair struct.
 *
 * This function takes a byte array and its length, and deserializes it into an
 * ElectionKeyPair struct using Protocol Buffers. It unpacks the data, copies the
 * guardian ID, deserializes the public key and the election polynomial.
 *
 * @param buffer Pointer to the byte array containing the serialized ElectionKeyPair data.
 * @param len The length of the byte array.
 * @param key_pair Pointer to the ElectionKeyPair struct to populate with the deserialized data.
 * @return 0 on success, or 1 on failure.
 */
int deserialize_election_key_pair(uint8_t* buffer, unsigned len, ElectionKeyPair* key_pair) {
    ElectionKeyPairProto* proto = election_key_pair_proto__unpack(NULL, len, buffer);
    if(proto == NULL) {
        ESP_LOGE("Deserialize ElectionKeyPair", "Failed to unpack proto");
        return 1;
    }

    memcpy(key_pair->guardian_id, proto->guardian_id.data, sizeof(key_pair->guardian_id));

    //Private key is never deserialized and should be empty anyway when sent over the network. This is to not free a non-allocated pointer
    key_pair->private_key = NULL;

    int bit_len;
    bit_len = (proto->public_key.len) * 8;
    key_pair->public_key = NULL;
    key_pair->public_key = (sp_int*)XMALLOC(MP_INT_SIZEOF(MP_BITS_CNT(bit_len)), NULL, DYNAMIC_TYPE_BIGINT);
    if(key_pair->public_key != NULL) {
        XMEMSET(key_pair->public_key, 0, MP_INT_SIZEOF(MP_BITS_CNT(bit_len)));
        sp_init_size(key_pair->public_key, MP_BITS_CNT(bit_len));
    }
    sp_read_unsigned_bin(key_pair->public_key, proto->public_key.data, proto->public_key.len);
    deserialize_election_polynomial(proto->polynomial, &key_pair->polynomial);

    election_key_pair_proto__free_unpacked(proto, NULL);
    return 0;
}

/**
 * @brief Serializes an ElectionPartialKeyVerification object into a byte array.
 *
 * This function serializes an ElectionPartialKeyVerification struct into a byte array
 * using Protocol Buffers. The serialized data includes the sender, receiver, verifier,
 * and the verification status.
 *
 * @param verification Pointer to the ElectionPartialKeyVerification object to serialize.
 * @param len Pointer to an unsigned integer that will store the length of the serialized byte array.
 * @return A pointer to the serialized byte array. The caller is responsible for freeing the allocated memory.
 */
uint8_t* serialize_election_partial_key_verification(ElectionPartialKeyVerification* verification, unsigned* len) {
    ElectionPartialKeyVerificationProto proto = ELECTION_PARTIAL_KEY_VERIFICATION_PROTO__INIT;
    proto.sender.len = sizeof(verification->sender);
    proto.sender.data = verification->sender;
    proto.receiver.len = sizeof(verification->receiver);
    proto.receiver.data = verification->receiver;
    proto.verifier.len = sizeof(verification->verifier);
    proto.verifier.data = verification->verifier;
    proto.verified = verification->verified;
    *len = election_partial_key_verification_proto__get_packed_size(&proto);
    uint8_t* buffer = (uint8_t *)calloc(*len, sizeof(char));
    election_partial_key_verification_proto__pack(&proto, buffer);
    return buffer;
}
/**
 * @brief Deserializes a byte array into an ElectionPartialKeyVerification struct.
 *
 * This function takes a byte array and its length, and deserializes it into an
 * ElectionPartialKeyVerification struct using Protocol Buffers. It unpacks the data and
 * copies the sender, receiver, verifier, and the verification status.
 *
 * @param buffer Pointer to the byte array containing the serialized ElectionPartialKeyVerification data.
 * @param len The length of the byte array.
 * @param verification Pointer to the ElectionPartialKeyVerification struct to populate with the deserialized data.
 * @return 0 on success, or 1 on failure.
 */
int deserialize_election_partial_key_verification(uint8_t* buffer, unsigned len, ElectionPartialKeyVerification* verification) {
    ElectionPartialKeyVerificationProto* proto = election_partial_key_verification_proto__unpack(NULL, len, buffer);
    if(proto == NULL) {
        ESP_LOGE("Deserialize ElectionPartialKeyVerification", "Failed to unpack proto");
        return 1;
    }
    memcpy(verification->sender, proto->sender.data, sizeof(verification->sender));
    memcpy(verification->receiver, proto->receiver.data, sizeof(verification->receiver));
    memcpy(verification->verifier, proto->verifier.data, sizeof(verification->verifier));
    verification->verified = proto->verified;
    election_partial_key_verification_proto__free_unpacked(proto, NULL);
    return 0;
}

/**
 * @brief Serializes an ElectionPartialKeyPairBackup object into a byte array.
 *
 * This function serializes an ElectionPartialKeyPairBackup struct into a byte array
 * using Protocol Buffers. The serialized data includes the sender, receiver, and the
 * encrypted coordinate (HashedElGamalCiphertext).
 *
 * @param backup Pointer to the ElectionPartialKeyPairBackup object to serialize.
 * @param len Pointer to an unsigned integer that will store the length of the serialized byte array.
 * @return A pointer to the serialized byte array. The caller is responsible for freeing the allocated memory.
 */
uint8_t* serialize_election_partial_key_backup(ElectionPartialKeyPairBackup* backup, unsigned* len) {
    ElectionPartialKeyPairBackupProto proto = ELECTION_PARTIAL_KEY_PAIR_BACKUP_PROTO__INIT;
    proto.sender.len = sizeof(backup->sender);
    proto.sender.data = backup->sender;
    proto.receiver.len = sizeof(backup->receiver);
    proto.receiver.data = backup->receiver;
    
    HashedElGamalCiphertextProto hash = HASHED_EL_GAMAL_CIPHERTEXT_PROTO__INIT;
    hash.pad.len = sp_unsigned_bin_size(backup->encrypted_coordinate.pad);
    hash.pad.data = (uint8_t*)malloc(hash.pad.len);
    sp_to_unsigned_bin(backup->encrypted_coordinate.pad, hash.pad.data);
    hash.data.len = sp_unsigned_bin_size(backup->encrypted_coordinate.data);
    hash.data.data = (uint8_t*)malloc(hash.data.len);
    sp_to_unsigned_bin(backup->encrypted_coordinate.data, hash.data.data);
    hash.mac.len = sp_unsigned_bin_size(backup->encrypted_coordinate.mac);
    hash.mac.data = (uint8_t*)malloc(hash.mac.len);
    sp_to_unsigned_bin(backup->encrypted_coordinate.mac, hash.mac.data);
    proto.encrypted_coordinate = &hash;
    
    *len = election_partial_key_pair_backup_proto__get_packed_size(&proto);
    uint8_t* buffer = (uint8_t *)calloc(*len, sizeof(char));
    election_partial_key_pair_backup_proto__pack(&proto, buffer);
    return buffer;
}

/**
 * @brief Deserializes a byte array into an ElectionPartialKeyPairBackup struct.
 *
 * This function takes a byte array and its length, and deserializes it into an
 * ElectionPartialKeyPairBackup struct using Protocol Buffers. It unpacks the data and
 * copies the sender, receiver, and the encrypted coordinate (HashedElGamalCiphertext).
 *
 * @param buffer Pointer to the byte array containing the serialized ElectionPartialKeyPairBackup data.
 * @param len The length of the byte array.
 * @param backup Pointer to the ElectionPartialKeyPairBackup struct to populate with the deserialized data.
 * @return 0 on success, or 1 on failure.
 */
int deserialize_election_partial_key_backup(uint8_t* buffer, unsigned len, ElectionPartialKeyPairBackup* backup) {
    ElectionPartialKeyPairBackupProto* msg = election_partial_key_pair_backup_proto__unpack(NULL, len, buffer);
    HashedElGamalCiphertextProto* hash = msg->encrypted_coordinate;
    if(msg == NULL) {
        ESP_LOGE("Deserialize ElectionPartialKeyPairBackup", "Failed to unpack proto");
        return 1;
    }
    memcpy(backup->sender, msg->sender.data, sizeof(backup->sender));
    memcpy(backup->receiver, msg->receiver.data, sizeof(backup->receiver));

    int bit_len;
    bit_len = (hash->pad.len) * 8;
    backup->encrypted_coordinate.pad = NULL;
    backup->encrypted_coordinate.pad = (sp_int*)XMALLOC(MP_INT_SIZEOF(MP_BITS_CNT(bit_len)), NULL, DYNAMIC_TYPE_BIGINT);
    if(backup->encrypted_coordinate.pad != NULL) {
        XMEMSET(backup->encrypted_coordinate.pad, 0, MP_INT_SIZEOF(MP_BITS_CNT(bit_len)));
        sp_init_size(backup->encrypted_coordinate.pad, MP_BITS_CNT(bit_len));
    }     
    sp_read_unsigned_bin(backup->encrypted_coordinate.pad, hash->pad.data, hash->pad.len);         

    bit_len = (hash->data.len) * 8;
    backup->encrypted_coordinate.data = NULL;
    backup->encrypted_coordinate.data = (sp_int*)XMALLOC(MP_INT_SIZEOF(MP_BITS_CNT(bit_len)), NULL, DYNAMIC_TYPE_BIGINT);
    if(backup->encrypted_coordinate.data != NULL) {
        XMEMSET(backup->encrypted_coordinate.data, 0, MP_INT_SIZEOF(MP_BITS_CNT(bit_len)));
        sp_init_size(backup->encrypted_coordinate.data, MP_BITS_CNT(bit_len));
    }     
    sp_read_unsigned_bin(backup->encrypted_coordinate.data, hash->data.data, hash->data.len);   

    bit_len = (hash->mac.len) * 8;
    backup->encrypted_coordinate.mac = NULL;
    backup->encrypted_coordinate.mac = (sp_int*)XMALLOC(MP_INT_SIZEOF(MP_BITS_CNT(bit_len)), NULL, DYNAMIC_TYPE_BIGINT);
    if(backup->encrypted_coordinate.mac != NULL) {
        XMEMSET(backup->encrypted_coordinate.mac, 0, MP_INT_SIZEOF(MP_BITS_CNT(bit_len)));
        sp_init_size(backup->encrypted_coordinate.mac, MP_BITS_CNT(bit_len));
    }     
    sp_read_unsigned_bin(backup->encrypted_coordinate.mac, hash->mac.data, hash->mac.len);                                                                                                                               
    election_partial_key_pair_backup_proto__free_unpacked(msg, NULL);
    return 0;
}


/**
 * @brief Deserializes a byte array into a CiphertextTally struct.
 *
 * This function takes a byte array and its length, and deserializes it into a
 * CiphertextTally struct using Protocol Buffers. It unpacks the data and populates
 * the tally object with contest and selection information.
 *
 * @param buffer Pointer to the byte array containing the serialized CiphertextTally data.
 * @param len The length of the byte array.
 * @param ciphertally Pointer to the CiphertextTally struct to populate with the deserialized data.
 * @return 0 on success, or -1 on failure.
 */
int deserialize_ciphertext_tally(uint8_t *buffer, unsigned len, CiphertextTally* ciphertally) {
    CiphertextTallyProto* tally = ciphertext_tally_proto__unpack(NULL, len, buffer);
    if (tally == NULL) {
        fprintf(stderr, "Error unpacking CiphertextTallySelections\n");
        return -1;
    }

    ciphertally->object_id = strdup(tally->object_id);
    ciphertally->base_hash = NULL;
    ciphertally->base_hash = (sp_int*)XMALLOC(MP_INT_SIZEOF(MP_BITS_CNT(256)), NULL, DYNAMIC_TYPE_BIGINT);
    sp_read_unsigned_bin(ciphertally->base_hash, tally->base_hash.data, tally->base_hash.len);
    

    ciphertally->num_contest = tally->num_contest;
    ciphertally->contests = (CiphertextTallyContest*)malloc(sizeof(CiphertextTallyContest) * ciphertally->num_contest);
    for(int i = 0; i < ciphertally->num_contest; i++) {
        ciphertally->contests[i].object_id = strdup(tally->contests[i]->object_id);
        ciphertally->contests[i].sequence_order = tally->contests[i]->sequence_order;
        ciphertally->contests[i].description_hash = NULL;
        ciphertally->contests[i].description_hash = (sp_int*)XMALLOC(MP_INT_SIZEOF(MP_BITS_CNT(256)), NULL, DYNAMIC_TYPE_BIGINT);
        sp_read_unsigned_bin(ciphertally->contests[i].description_hash, tally->contests[i]->description_hash.data, tally->contests[i]->description_hash.len);
        ciphertally->contests[i].num_selections = tally->contests[i]->num_selections;

        ciphertally->contests[i].selections = (CiphertextTallySelection*)malloc(sizeof(CiphertextTallySelection) * ciphertally->contests[i].num_selections);
        for(int j = 0; j < ciphertally->contests[i].num_selections; j++) {
            ciphertally->contests[i].selections[j].object_id = strdup(tally->contests[i]->selections[j]->object_id);
            ciphertally->contests[i].selections[j].ciphertext_pad = NULL;
            ciphertally->contests[i].selections[j].ciphertext_pad = (sp_int*)XMALLOC(MP_INT_SIZEOF(MP_BITS_CNT(3072)), NULL, DYNAMIC_TYPE_BIGINT);
            sp_read_unsigned_bin(ciphertally->contests[i].selections[j].ciphertext_pad, tally->contests[i]->selections[j]->ciphertext_pad.data, tally->contests[i]->selections[j]->ciphertext_pad.len);
            ciphertally->contests[i].selections[j].ciphertext_data = NULL;
            ciphertally->contests[i].selections[j].ciphertext_data = (sp_int*)XMALLOC(MP_INT_SIZEOF(MP_BITS_CNT(3072)), NULL, DYNAMIC_TYPE_BIGINT);
            sp_read_unsigned_bin(ciphertally->contests[i].selections[j].ciphertext_data, tally->contests[i]->selections[j]->ciphertext_data.data, tally->contests[i]->selections[j]->ciphertext_data.len);
        }
    
    }
    ciphertext_tally_proto__free_unpacked(tally, NULL);
    return 0;
}

/**
 * @brief Serializes a DecryptionShare object into a byte array.
 *
 * This function serializes a DecryptionShare struct into a byte array using Protocol Buffers.
 * It includes information about the guardian, contests, and selections, along with their
 * corresponding decryption proofs.
 *
 * @param share Pointer to the DecryptionShare object to serialize.
 * @param len Pointer to an unsigned integer that will store the length of the serialized byte array.
 * @return A pointer to the serialized byte array. The caller is responsible for freeing the allocated memory.
 */
uint8_t* serialize_DecryptionShare(DecryptionShare* share, unsigned* len) {
    DecryptionShareProto proto = DECRYPTION_SHARE_PROTO__INIT;
    CiphertextDecryptionContestProto** contests;
    CiphertextDecryptionSelectionProto** selections;

    proto.object_id = strdup(share->object_id);
    proto.guardian_id.len = sizeof(share->guardian_id);
    proto.guardian_id.data = share->guardian_id;
    proto.public_key.len = sp_unsigned_bin_size(share->public_key);
    proto.public_key.data = (uint8_t*)malloc(proto.public_key.len);
    sp_to_unsigned_bin(share->public_key, proto.public_key.data);
    proto.num_contests = share->num_contest;
    proto.n_contests = share->num_contest;

    contests = (CiphertextDecryptionContestProto**)malloc(sizeof(CiphertextDecryptionContestProto*) * share->num_contest);
    
    for(int i = 0; i < share->num_contest; i++) {
        contests[i] = (CiphertextDecryptionContestProto*)malloc(sizeof(CiphertextDecryptionContestProto));
        ciphertext_decryption_contest_proto__init(contests[i]);
        contests[i]->object_id = strdup(share->contests[i].object_id);

        contests[i]->guardian_id.len = sizeof(share->guardian_id);
        contests[i]->guardian_id.data = share->guardian_id;

        contests[i]->description_hash.len = sp_unsigned_bin_size(share->contests[i].description_hash);
        contests[i]->description_hash.data = (uint8_t*)malloc(contests[i]->description_hash.len);
        sp_to_unsigned_bin(share->contests[i].description_hash, contests[i]->description_hash.data);
        
        contests[i]->n_selections = share->contests[i].num_selections;
        contests[i]->num_selections = share->contests[i].num_selections;
        
        selections = (CiphertextDecryptionSelectionProto**)malloc(sizeof(CiphertextDecryptionSelectionProto*) * share->contests[i].num_selections);
        for(int j = 0; j < share->contests[i].num_selections; j++) {
            selections[j] = (CiphertextDecryptionSelectionProto*)malloc(sizeof(CiphertextDecryptionSelectionProto));
            ciphertext_decryption_selection_proto__init(selections[j]);
            selections[j]->object_id = strdup(share->contests[i].selections[j].object_id);
            selections[j]->guardian_id.len = sizeof(share->contests[i].selections[j].guardian_id);
            selections[j]->guardian_id.data = share->contests[i].selections[j].guardian_id;

            selections[j]->decryption.len = sp_unsigned_bin_size(share->contests[i].selections[j].decryption);
            selections[j]->decryption.data = (uint8_t*)malloc(selections[j]->decryption.len);
            sp_to_unsigned_bin(share->contests[i].selections[j].decryption, selections[j]->decryption.data);
            
            selections[j]->proof_pad.len = sp_unsigned_bin_size(share->contests[i].selections[j].proof.pad);
            selections[j]->proof_pad.data = (uint8_t*)malloc(selections[j]->proof_pad.len);
            sp_to_unsigned_bin(share->contests[i].selections[j].proof.pad, selections[j]->proof_pad.data);

            selections[j]->proof_data.len = sp_unsigned_bin_size(share->contests[i].selections[j].proof.data);
            selections[j]->proof_data.data = (uint8_t*)malloc(selections[j]->proof_data.len);
            sp_to_unsigned_bin(share->contests[i].selections[j].proof.data, selections[j]->proof_data.data);

            selections[j]->proof_challenge.len = sp_unsigned_bin_size(share->contests[i].selections[j].proof.challenge);
            selections[j]->proof_challenge.data = (uint8_t*)malloc(selections[j]->proof_challenge.len);
            sp_to_unsigned_bin(share->contests[i].selections[j].proof.challenge, selections[j]->proof_challenge.data);

            selections[j]->proof_response.len = sp_unsigned_bin_size(share->contests[i].selections[j].proof.response);
            selections[j]->proof_response.data = (uint8_t*)malloc(selections[j]->proof_response.len);
            sp_to_unsigned_bin(share->contests[i].selections[j].proof.response, selections[j]->proof_response.data);
        }
        contests[i]->selections = selections;
    }
    proto.contests = contests;
    
    *len = decryption_share_proto__get_packed_size(&proto);
    uint8_t* buffer = (uint8_t *)calloc(*len, sizeof(char));
    decryption_share_proto__pack(&proto, buffer);
    return buffer;
}

