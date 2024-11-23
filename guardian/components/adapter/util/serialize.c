#include "serialize.h"
/*

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
*/

char uint8_to_string(uint8_t* array) {
    char hex[sizeof(array) * 2 + 1];
    for(int i = 0; i < sizeof(array); i++) {
        sprintf(&hex[2*i], "%02x", array[i]);
    }
    hex[sizeof(array) * 2] = '\0';
    return hex;
}

static cJSON* schnorr_proof_to_json(SchnorrProof* proof) {
    cJSON* json = cJSON_CreateObject();
    int size;
    sp_radix_size(proof->pubkey, 16, &size);
    char* buffer = (char*)malloc(size);
    if(buffer == NULL) {
        cJSON_Delete(json);
        return NULL;
    }
    sp_tohex(proof->pubkey, buffer);
    cJSON_AddStringToObject(json, "pubkey", buffer);
    sp_radix_size(proof->commitment, 16, &size);
    buffer = (char*)realloc(buffer, size);
    if(buffer == NULL) {
        cJSON_Delete(json);
        return NULL;
    }
    sp_tohex(proof->commitment, buffer);
    cJSON_AddStringToObject(json, "commitment", buffer);
    sp_radix_size(proof->challenge, 16, &size);
    buffer = (char*)realloc(buffer, size);
    if(buffer == NULL) {
        cJSON_Delete(json);
        return NULL;
    }
    sp_tohex(proof->challenge, buffer);
    cJSON_AddStringToObject(json, "challenge", buffer);
    sp_radix_size(proof->response, 16, &size);
    buffer = (char*)realloc(buffer, size);
    if(buffer == NULL) {
        cJSON_Delete(json);
        return NULL;
    }
    sp_tohex(proof->response, buffer);
    cJSON_AddStringToObject(json, "response", buffer);
    free(buffer);
    return json;
}

static cJSON* coefficient_to_json(Coefficient* coefficient) {
    cJSON* json = cJSON_CreateObject();
    int size;
    sp_radix_size(coefficient->value, 16, &size);
    char* buffer = (char*)malloc(size);
    if(buffer == NULL) {
        cJSON_Delete(json);
        return NULL;
    }
    sp_tohex(coefficient->value, buffer);
    cJSON_AddStringToObject(json, "value", buffer);
    sp_radix_size(coefficient->commitment, 16, &size);
    buffer = (char*)realloc(buffer, size);
    if(buffer == NULL) {
        cJSON_Delete(json);
        return NULL;
    }
    sp_tohex(coefficient->commitment, buffer);
    cJSON_AddStringToObject(json, "commitment", buffer);
    cJSON* schnorr = schnorr_proof_to_json(&coefficient->proof);
    cJSON_AddItemToObject(json, "SchnorrProof",schnorr);
    free(buffer);
    return json;
}

static cJSON* election_polynomial_to_json(ElectionPolynomial* polynomial) {
    cJSON* json = cJSON_CreateObject();
    cJSON_AddNumberToObject(json, "num_polynomial", polynomial->num_coefficients);
    cJSON* coefficients = cJSON_CreateArray();
    for (int i = 0; i < polynomial->num_coefficients; i++) {
        cJSON* coefficient = coefficient_to_json(&polynomial->coefficients[i]);
        cJSON_AddItemToArray(coefficients, coefficient);
    }
    cJSON_AddItemToObject(json, "coefficients", coefficients);
    return json;
}

char* serialize_election_key_pair(ElectionKeyPair* key_pair) {
    cJSON* json = cJSON_CreateObject();
    //cJSON_AddStringToObject(json, "guardian_id", uint8_to_string(&key_pair->guardian_id));
    int hex_size;
    sp_radix_size(key_pair->public_key, 16, &hex_size);
    char* hex_str = (char*)malloc(hex_size);
    sp_tohex(key_pair->public_key, hex_str);
    cJSON_AddStringToObject(json, "public_key", hex_str);
    cJSON* poly = election_polynomial_to_json(&key_pair->polynomial);
    cJSON_AddItemToObject(json, "ElectionPolynomial", poly);
    char *serialized = cJSON_PrintUnformatted(json);
    cJSON_Delete(json);
    free(hex_str);
    return serialized;
}

static cJSON* hashed_elgamal_ciphertext_to_json(HashedElGamalCiphertext* ciphertext) {
    cJSON* json = cJSON_CreateObject();
    int size;
    sp_radix_size(ciphertext->pad, 16, &size);
    char* buffer = (char*)malloc(size);
    if(buffer == NULL) {
        cJSON_Delete(json);
        return NULL;
    }
    sp_tohex(ciphertext->pad, buffer);
    cJSON_AddStringToObject(json, "pad", buffer);
    sp_radix_size(ciphertext->data, 16, &size);
    buffer = (char*)realloc(buffer, size);
    if(buffer == NULL) {
        cJSON_Delete(json);
        return NULL;
    }
    sp_tohex(ciphertext->data, buffer);
    cJSON_AddStringToObject(json, "data", buffer);
    sp_radix_size(ciphertext->mac, 16, &size);
    buffer = (char*)realloc(buffer, size);
    if(buffer == NULL) {
        cJSON_Delete(json);
        return NULL;
    }
    sp_tohex(ciphertext->mac, buffer);
    cJSON_AddStringToObject(json, "mac", buffer);
    free(buffer);
    return json;
}

char* serialize_election_partial_key_backup(ElectionPartialKeyPairBackup* backup) {
    cJSON* json = cJSON_CreateObject();
    //cJSON_AddStringToObject(json, "sender", uint8_to_string(&backup->sender));
    //cJSON_AddStringToObject(json, "receiver", uint8_to_string(&backup->sender));
    cJSON* hash = hashed_elgamal_ciphertext_to_json(&backup->encrypted_coordinate);
    cJSON_AddItemToObject(json, "HashedElGamalCiphertext", hash);
    char *serialized = cJSON_PrintUnformatted(json);
    cJSON_Delete(json);
    return serialized;
}

char* serialize_election_partial_key_verification(ElectionPartialKeyVerification* verification) {
    cJSON* json = cJSON_CreateObject();
    //cJSON_AddStringToObject(json, "sender", uint8_to_string(&verification->sender));
    //cJSON_AddStringToObject(json, "receiver", uint8_to_string(&verification->receiver));
    //cJSON_AddStringToObject(json, "verifier", uint8_to_string(&verification->verifier));
    cJSON_AddBoolToObject(json, "verified", verification->verified);
    char *serialized = cJSON_PrintUnformatted(json);
    cJSON_Delete(json);
    return serialized;
}


/*

ElectionKeyPair* deserialize_election_key_pair(const char* json_string) {

}



ElectionPartialKeyPairBackup* deserialize_election_partial_key_backup(const char* json_string) {

}




ElectionPartialKeyVerification* deserialize_election_partial_key_verification(const char* json_string) {

}
*/
