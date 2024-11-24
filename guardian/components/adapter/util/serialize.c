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

 
 typedef struct {
    uint8_t sender[6];
    uint8_t receiver[6];
    uint8_t verifier[6];
    bool verified;
 } ElectionPartialKeyVerification;

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
    return verification;
}