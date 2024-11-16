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
    ElectionPartialKeyPairBackup backup;
    ElectionKeyPair sender;
    ElectionKeyPair receiver;
    sender.guardian_id = 1;
    receiver.guardian_id = 2;
    generate_election_key_pair(2, &sender);
    generate_election_key_pair(2, &receiver);

    DECL_MP_INT_SIZE(coordinate, 256);
    NEW_MP_INT_SIZE(coordinate, 256, NULL, DYNAMIC_TYPE_BIGINT);
    INIT_MP_INT_SIZE(coordinate, 256);
    generate_election_partial_key_backup(&sender, &receiver, &backup);
}