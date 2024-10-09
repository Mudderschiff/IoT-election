#include "model.h"
#include "freertos/task.h"
#include "freertos/FreeRTOS.h"


/*
Key Ceremony:
Round 1: Announce and Share keys
client_id/publickey
mqtt broker check: all_guardians_annouced = #/public_keys = NUMBER_OF_GUARDIANS
	
Round 2
Each guardian generated election partial key backups
For each #/public_key generate_election_partial_key_backup
MQTT Broker: Each guardian needs NUMBER_OF_GUARDIANS - 1 Partial key backups
	
client_id/guardian_id/ElectionPartialKeyBackup
Round 3
client_id/guardian_id/ElectionPartialKeyVerification
verify_polynomial_coordinate
MQTT Broker: all_backups_verified True Confirms all guardians have verified the backups of all other guardians
receive_backup_verifications
Final
MQTT Broker: if all backups verified. combine_election_public_keys (pub key + commitment hash)
*/


void app_main(void) {
    SchnorrProof proof;
    DECL_MP_INT_SIZE(pubkey, 3072);
    NEW_MP_INT_SIZE(pubkey, 3072, NULL, DYNAMIC_TYPE_BIGINT);
    INIT_MP_INT_SIZE(pubkey, 3072);

    DECL_MP_INT_SIZE(seckey, 256);
    NEW_MP_INT_SIZE(seckey, 256, NULL, DYNAMIC_TYPE_BIGINT);
    INIT_MP_INT_SIZE(seckey, 256);

    DECL_MP_INT_SIZE(nonce, 256);
    NEW_MP_INT_SIZE(nonce, 256, NULL, DYNAMIC_TYPE_BIGINT);
    INIT_MP_INT_SIZE(nonce, 256);
    rand_q(nonce);
    rand_q(seckey);
    g_pow_p(seckey, pubkey);
    make_schnorr_proof(seckey, pubkey, nonce, &proof);

    /*
        proof.pubkey = (mp_int*)XMALLOC(MP_INT_SIZEOF(MP_BITS_CNT(256)), NULL, DYNAMIC_TYPE_BIGINT);
    if (proof.pubkey != NULL) {
        XMEMSET(proof.pubkey, 0, MP_INT_SIZEOF(MP_BITS_CNT(256)));
    }
    //mp_init_size(proof.pubkey, MP_BITS_CNT(256))
    FREE_MP_INT_SIZE(proof.pubkey, NULL, DYNAMIC_TYPE_BIGINT);
    */
    sp_zero(pubkey);
    sp_zero(seckey);
    sp_zero(nonce);
    FREE_MP_INT_SIZE(proof.challenge, NULL, DYNAMIC_TYPE_BIGINT);
    FREE_MP_INT_SIZE(proof.commitment, NULL, DYNAMIC_TYPE_BIGINT);
    FREE_MP_INT_SIZE(proof.pubkey, NULL, DYNAMIC_TYPE_BIGINT);
    FREE_MP_INT_SIZE(proof.response, NULL, DYNAMIC_TYPE_BIGINT);

    FREE_MP_INT_SIZE(pubkey, NULL, DYNAMIC_TYPE_BIGINT);
    FREE_MP_INT_SIZE(seckey, NULL, DYNAMIC_TYPE_BIGINT);
    FREE_MP_INT_SIZE(nonce, NULL, DYNAMIC_TYPE_BIGINT);

}