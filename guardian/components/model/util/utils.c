#include "utils.h"

/** 
 * @brief Print the value of a sp_int
 * @param num: The number to print
 * @return void
*/
/*
void print_sp_int(sp_int *num) {   
    int size = sp_unsigned_bin_size(num);
    char *buffer = (char *)calloc(size * 2 + 1, sizeof(char));
    if (buffer == NULL) {
        ESP_LOGE("Print mp_int", "Failed to allocate memory for buffer");
        return;
    }
    if (sp_toradix(num, buffer, 16) == MP_OKAY) {
        ESP_LOGI("Print mp_int", "mp_int value: %s", buffer);
    } else {
        ESP_LOGE("Print mp_int", "Failed to convert mp_int to string");
    }
    free(buffer);
}
*/

/*
void int_to_bytes(int value, unsigned char *bytes) {
    for (int i = 0; i < 4; i++) {
        bytes[3 - i] = (value >> (i * 8)) & 0xFF;
    }
}

// Function to print byte array
void print_byte_array(const byte *array, int size) {
    char buffer[size * 3 + 1]; // Each byte will be represented by 2 hex digits and a space
    for (int i = 0; i < size; i++) {
        sprintf(&buffer[i * 3], "%02x ", array[i]);
    }
    buffer[size * 3] = '\0'; // Null-terminate the string
    ESP_LOGI("BYTE_ARRAY", "%s", buffer);
}
*/
#include <stdlib.h>
#include "utils.h"

// Free function for CiphertextTallySelection
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

// Free function for CiphertextTallyContest
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

// Free function for CiphertextTally
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

// Free function for ChaumPedersenProof
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

// Free function for CiphertextDecryptionSelection
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

// Free function for CiphertextDecryptionContest
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

// Free function for DecryptionShare
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