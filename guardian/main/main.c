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
    ElGamalKeyPair key_pair;
    key_pair.secret_key = (sp_int*)XMALLOC(MP_INT_SIZEOF(MP_BITS_CNT(256)), NULL, DYNAMIC_TYPE_BIGINT);
    key_pair.public_key = (sp_int*)XMALLOC(MP_INT_SIZEOF(MP_BITS_CNT(3072)), NULL, DYNAMIC_TYPE_BIGINT);
    if (key_pair.secret_key != NULL) {
        XMEMSET(key_pair.secret_key, 0, MP_INT_SIZEOF(MP_BITS_CNT(256)));
        mp_init_size(key_pair.secret_key, MP_BITS_CNT(256));
    }
    if (key_pair.public_key != NULL) {
        XMEMSET(key_pair.public_key, 0, MP_INT_SIZEOF(MP_BITS_CNT(3072)));
        mp_init_size(key_pair.public_key, MP_BITS_CNT(3072));
    }
    
    generate_election_key_pair(5, &key_pair);
    print_sp_int(key_pair.secret_key);
    print_sp_int(key_pair.public_key);
}