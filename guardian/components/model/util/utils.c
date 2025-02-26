#include "utils.h"
#include <stdlib.h>

/**
 * @brief Frees the memory allocated for a CiphertextTallySelection struct.
 *
 * This function releases the memory associated with the object_id,
 * ciphertext_pad, and ciphertext_data members of the CiphertextTallySelection struct.
 * It also sets these pointers to NULL to prevent double freeing.
 *
 * @param selection A pointer to the CiphertextTallySelection object to free.
 *                  If selection is NULL, the function returns immediately.
 */
void free_CiphertextTallySelection(CiphertextTallySelection* selection) {
    if (selection == NULL) return;

    if (selection->object_id != NULL) {
        free(selection->object_id);
        selection->object_id = NULL;
    }

    if (selection->ciphertext_pad != NULL) {
        FREE_MP_INT_SIZE(selection->ciphertext_pad, NULL, DYNAMIC_TYPE_BIGINT);
        selection->ciphertext_pad = NULL;
    }

    if (selection->ciphertext_data != NULL) {
        FREE_MP_INT_SIZE(selection->ciphertext_data, NULL, DYNAMIC_TYPE_BIGINT);
        selection->ciphertext_data = NULL;
    }
}

/**
 * @brief Frees the memory allocated for a CiphertextTallyContest struct.
 *
 * This function releases the memory associated with the object_id,
 * description_hash, and selections members of the CiphertextTallyContest struct.
 * It iterates through the selections array and calls free_CiphertextTallySelection
 * for each element before freeing the array itself.  It also sets pointers to NULL
 * to prevent double freeing.
 *
 * @param contest A pointer to the CiphertextTallyContest struct to free.
 *                If contest is NULL, the function returns immediately.
 */
void free_CiphertextTallyContest(CiphertextTallyContest* contest) {
    if (contest == NULL) return;

    if (contest->object_id != NULL) {
        free(contest->object_id);
        contest->object_id = NULL;
    }

    if (contest->description_hash != NULL) {
        FREE_MP_INT_SIZE(contest->description_hash, NULL, DYNAMIC_TYPE_BIGINT);
        contest->description_hash = NULL;
    }

    if (contest->selections != NULL) {
        for (int i = 0; i < contest->num_selections; ++i) {
            free_CiphertextTallySelection(&contest->selections[i]);
        }
        free(contest->selections);
        contest->selections = NULL;
    }
}

/**
 * @brief Frees the memory allocated for a CiphertextTally struct.
 *
 * This function releases the memory associated with the object_id,
 * base_hash, and contests members of the CiphertextTally struct.
 * It iterates through the contests array and calls free_CiphertextTallyContest
 * for each element before freeing the array itself. It also sets pointers to NULL
 * to prevent double freeing.
 *
 * @param tally A pointer to the CiphertextTally struct to free.
 *              If tally is NULL, the function returns immediately.
 */
void free_CiphertextTally(CiphertextTally* tally) {
    if (tally == NULL) return;

    if (tally->object_id != NULL) {
        free(tally->object_id);
        tally->object_id = NULL;
    }

    if (tally->base_hash != NULL) {
        FREE_MP_INT_SIZE(tally->base_hash, NULL, DYNAMIC_TYPE_BIGINT);
        tally->base_hash = NULL;
    }

    if (tally->contests != NULL) {
        for (int i = 0; i < tally->num_contest; ++i) {
            free_CiphertextTallyContest(&tally->contests[i]);
        }
        free(tally->contests);
        tally->contests = NULL;
    }
}

/**
 * @brief Frees the memory allocated for a ChaumPedersenProof struct.
 *
 * This function releases the memory associated with the pad, data, challenge,
 * and response members of the ChaumPedersenProof struct. It also sets these
 * pointers to NULL to prevent double freeing.
 *
 * @param proof A pointer to the ChaumPedersenProof struct to free.
 *              If proof is NULL, the function returns immediately.
 */
void free_ChaumPedersenProof(ChaumPedersenProof* proof) {
    if (proof == NULL) return;

    if (proof->pad != NULL) {
        FREE_MP_INT_SIZE(proof->pad, NULL, DYNAMIC_TYPE_BIGINT);
        proof->pad = NULL;
    }

    if (proof->data != NULL) {
        FREE_MP_INT_SIZE(proof->data, NULL, DYNAMIC_TYPE_BIGINT);
        proof->data = NULL;
    }

    if (proof->challenge != NULL) {
        FREE_MP_INT_SIZE(proof->challenge, NULL, DYNAMIC_TYPE_BIGINT);
        proof->challenge = NULL;
    }

    if (proof->response != NULL) {
        FREE_MP_INT_SIZE(proof->response, NULL, DYNAMIC_TYPE_BIGINT);
        proof->response = NULL;
    }
}

/**
 * @brief Frees the memory allocated for a CiphertextDecryptionSelection struct.
 *
 * This function releases the memory associated with the object_id and
 * decryption members of the CiphertextDecryptionSelection struct. It also calls
 * free_ChaumPedersenProof to free the proof member. It sets pointers to NULL
 * to prevent double freeing.
 *
 * @param selection A pointer to the CiphertextDecryptionSelection struct to free.
 *                  If selection is NULL, the function returns immediately.
 */
void free_CiphertextDecryptionSelection(CiphertextDecryptionSelection* selection) {
    if (selection == NULL) return;

    if (selection->object_id != NULL) {
        free(selection->object_id);
        selection->object_id = NULL;
    }

    if (selection->decryption != NULL) {
        FREE_MP_INT_SIZE(selection->decryption, NULL, DYNAMIC_TYPE_BIGINT);
        selection->decryption = NULL;
    }

    free_ChaumPedersenProof(&selection->proof);
}

/**
 * @brief Frees the memory allocated for a CiphertextDecryptionContest struct.
 *
 * This function releases the memory associated with the object_id,
 * description_hash, and selections members of the CiphertextDecryptionContest struct.
 * It iterates through the selections array and calls
 * free_CiphertextDecryptionSelection for each element before freeing the array
 * itself. It also sets pointers to NULL to prevent double freeing.
 *
 * @param contest A pointer to the CiphertextDecryptionContest struct to free.
 *                If contest is NULL, the function returns immediately.
 */
void free_CiphertextDecryptionContest(CiphertextDecryptionContest* contest) {
    if (contest == NULL) return;

    if (contest->object_id != NULL) {
        free(contest->object_id);
        contest->object_id = NULL;
    }

    if (contest->description_hash != NULL) {
        FREE_MP_INT_SIZE(contest->description_hash, NULL, DYNAMIC_TYPE_BIGINT);
        contest->description_hash = NULL;
    }

    if (contest->selections != NULL) {
        for (int i = 0; i < contest->num_selections; ++i) {
            free_CiphertextDecryptionSelection(&contest->selections[i]);
        }
        free(contest->selections);
        contest->selections = NULL;
    }
}

/**
 * @brief Frees the memory allocated for a DecryptionShare struct.
 *
 * This function releases the memory associated with the object_id, public_key,
 * and contests members of the DecryptionShare struct. It iterates through the
 * contests array and calls free_CiphertextDecryptionContest for each element
 * before freeing the array itself. It also sets pointers to NULL to prevent
 * double freeing.
 *
 * @param share A pointer to the DecryptionShare struct to free.
 *              If share is NULL, the function returns immediately.
 */
void free_DecryptionShare(DecryptionShare* share) {
    if (share == NULL) return;

    if (share->object_id != NULL) {
        free(share->object_id);
        share->object_id = NULL;
    }

    if (share->public_key != NULL) {
        FREE_MP_INT_SIZE(share->public_key, NULL, DYNAMIC_TYPE_BIGINT);
        share->public_key = NULL;
    }

    if (share->contests != NULL) {
        for (int i = 0; i < share->num_contest; ++i) {
            free_CiphertextDecryptionContest(&share->contests[i]);
        }
        free(share->contests);
        share->contests = NULL;
    }
}
/**
 * @brief Frees the memory allocated for an ElectionPartialKeyPairBackup struct.
 *
 * This function releases the memory associated with the encrypted_coordinate
 * members of the ElectionPartialKeyPairBackup struct. It also sets pointers to NULL
 * to prevent double freeing.
 *
 * @param backup A pointer to the ElectionPartialKeyPairBackup struct to free.
 *               If backup is NULL, the function returns immediately.
 */
void free_ElectionPartialKeyPairBackup(ElectionPartialKeyPairBackup* backup) {
    if (backup == NULL) return;

    if (backup->encrypted_coordinate.pad != NULL) {
        FREE_MP_INT_SIZE(backup->encrypted_coordinate.pad, NULL, DYNAMIC_TYPE_BIGINT);
        backup->encrypted_coordinate.pad = NULL;
    }

    if (backup->encrypted_coordinate.data != NULL) {
        FREE_MP_INT_SIZE(backup->encrypted_coordinate.data, NULL, DYNAMIC_TYPE_BIGINT);
        backup->encrypted_coordinate.data = NULL;
    }

    if (backup->encrypted_coordinate.mac != NULL) {
        FREE_MP_INT_SIZE(backup->encrypted_coordinate.mac, NULL, DYNAMIC_TYPE_BIGINT);
        backup->encrypted_coordinate.mac = NULL;
    }
}

/**
 * @brief Frees the memory allocated for an ElectionKeyPair struct.
 *
 * This function releases the memory associated with the public_key and
 * private_key members of the ElectionKeyPair struct. It also calls
 * free_ElectionPolynomial to free the polynomial member. It sets pointers to NULL
 * to prevent double freeing.  The private key is zeroed out before freeing.
 *
 * @param key_pair A pointer to the ElectionKeyPair struct to free.
 *                 If key_pair is NULL, the function returns immediately.
 */
void free_ElectionKeyPair(ElectionKeyPair* key_pair) {
    if (key_pair == NULL) return;

    if (key_pair->public_key != NULL) {
        FREE_MP_INT_SIZE(key_pair->public_key, NULL, DYNAMIC_TYPE_BIGINT);
        key_pair->public_key = NULL;
    }

    if (key_pair->private_key != NULL) {
        //make sure to zero out the private key before freeing it
        sp_zero(key_pair->private_key);
        FREE_MP_INT_SIZE(key_pair->private_key, NULL, DYNAMIC_TYPE_BIGINT);
        key_pair->private_key = NULL;
    }

    free_ElectionPolynomial(&key_pair->polynomial);
}

/**
 * @brief Frees the memory allocated for an ElectionPolynomial struct.
 *
 * This function releases the memory associated with the coefficients
 * member of the ElectionPolynomial struct. It iterates through the
 * coefficients array and calls free_Coefficient for each element
 * before freeing the array itself. It also sets the pointer to NULL to prevent
 * double freeing.
 *
 * @param polynomial A pointer to the ElectionPolynomial struct to free.
 *                   If polynomial is NULL, the function returns immediately.
 */
void free_ElectionPolynomial(ElectionPolynomial* polynomial) {
    if (polynomial == NULL) return;

    if (polynomial->coefficients != NULL) {
        for (int i = 0; i < polynomial->num_coefficients; ++i) {
            free_Coefficient(&polynomial->coefficients[i]);
        }
        free(polynomial->coefficients);
        polynomial->coefficients = NULL;
    }
}

/**
 * @brief Frees the memory allocated for a Coefficient struct.
 *
 * This function releases the memory associated with the commitment and value
 * members of the Coefficient struct. It also calls free_SchnorrProof to free
 * the proof member. It sets pointers to NULL to prevent double freeing.
 *
 * @param coefficient A pointer to the Coefficient struct to free.
 *                    If coefficient is NULL, the function returns immediately.
 */
void free_Coefficient(Coefficient* coefficient) {
    if (coefficient == NULL) return;

    if (coefficient->commitment != NULL) {
        FREE_MP_INT_SIZE(coefficient->commitment, NULL, DYNAMIC_TYPE_BIGINT);
        coefficient->commitment = NULL;
    }
    if (coefficient->value != NULL) {
        FREE_MP_INT_SIZE(coefficient->value, NULL, DYNAMIC_TYPE_BIGINT);
        coefficient->value = NULL;
    }
    free_SchnorrProof(&coefficient->proof);
}

/**
 * @brief Frees the memory allocated for a SchnorrProof struct.
 *
 * This function releases the memory associated with the pubkey, commitment,
 * challenge, and response members of the SchnorrProof struct. It also sets
 * pointers to NULL to prevent double freeing.
 *
 * @param proof A pointer to the SchnorrProof struct to free.
 *              If proof is NULL, the function returns immediately.
 */
void free_SchnorrProof(SchnorrProof* proof) {
    if (proof == NULL) return;

    if (proof->pubkey != NULL) {
        FREE_MP_INT_SIZE(proof->pubkey, NULL, DYNAMIC_TYPE_BIGINT);
        proof->pubkey = NULL;
    }
    if (proof->commitment != NULL) {
        FREE_MP_INT_SIZE(proof->pubkey, NULL, DYNAMIC_TYPE_BIGINT);
        proof->commitment = NULL;
    }
    if (proof->challenge != NULL) {
        FREE_MP_INT_SIZE(proof->pubkey, NULL, DYNAMIC_TYPE_BIGINT);
        proof->challenge = NULL;
    }

    if (proof->response != NULL) {
        FREE_MP_INT_SIZE(proof->pubkey, NULL, DYNAMIC_TYPE_BIGINT);
        proof->response = NULL;
    }
}