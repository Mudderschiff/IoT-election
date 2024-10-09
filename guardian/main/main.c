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
    int num_coefficients = 5;
    Coefficient polynomial[num_coefficients];
    generate_polynomial(num_coefficients, polynomial);
    for (int i=0; i<num_coefficients; i++) {
        ESP_LOGI("Coefficient", "Coefficient %d", i);
        ESP_LOGI("Coefficient", "Value");
        print_sp_int(polynomial[i].value);
        ESP_LOGI("Coefficient", "Commitment");
        print_sp_int(polynomial[i].commitment);
        ESP_LOGI("Coefficient", "Proof.pubkey");
        print_sp_int(polynomial[i].proof.pubkey);
        ESP_LOGI("Coefficient", "Proof.commitment");
        print_sp_int(polynomial[i].proof.commitment);
        ESP_LOGI("Coefficient", "Proof.challenge");
        print_sp_int(polynomial[i].proof.challenge);
        ESP_LOGI("Coefficient", "Proof.response");
        print_sp_int(polynomial[i].proof.response);     
    }

    //free polynomials and proofs
}