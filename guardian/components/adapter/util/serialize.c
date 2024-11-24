#include "serialize.h"
#include "buff.pb-c.h"


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

/*
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
    NEW_MP_INT_SIZE(backup->encrypted_coordinate.pad, bit_len, NULL, DYNAMIC_TYPE_BIGINT);
    INIT_MP_INT_SIZE(backup->encrypted_coordinate.pad, bit_len);
    int err = sp_read_unsigned_bin(backup->encrypted_coordinate.pad, hash->pad.data, bit_len);
    if(err != 0) {
        ESP_LOGE("Deserialize ElectionPartialKeyPairBackup", "Failed to read pad");
        return 1;
    }

    bit_len = (hash->data.len) * 8;
    backup->encrypted_coordinate.data = NULL;
    NEW_MP_INT_SIZE(backup->encrypted_coordinate.data, bit_len, NULL, DYNAMIC_TYPE_BIGINT);
    INIT_MP_INT_SIZE(backup->encrypted_coordinate.data, bit_len);
    sp_read_unsigned_bin(backup->encrypted_coordinate.data, hash->data.data, bit_len);

    bit_len = (hash->mac.len) * 8;
    backup->encrypted_coordinate.mac = NULL;
    NEW_MP_INT_SIZE(backup->encrypted_coordinate.mac, bit_len, NULL, DYNAMIC_TYPE_BIGINT);
    INIT_MP_INT_SIZE(backup->encrypted_coordinate.mac, bit_len);
    sp_read_unsigned_bin(backup->encrypted_coordinate.mac, hash->mac.data, bit_len);

    election_partial_key_pair_backup_proto__free_unpacked(msg, NULL);
    return 0;
}






