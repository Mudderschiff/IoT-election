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