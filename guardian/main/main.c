#include "model.h"
#include "adapter.h"
#include "serialize.h"
#include "freertos/task.h"
#include "freertos/FreeRTOS.h"
#include "nvs_flash.h"
#include "protocol_examples_common.h"


static const char *TAG = "mqtt_example";

void app_main(void)
{
    ElectionPartialKeyPairBackup backup;
    ElectionPartialKeyVerification verification;
    ElectionKeyPair sender;
    ElectionKeyPair receiver;
    sender.guardian_id = 1;
    receiver.guardian_id = 2;
    generate_election_key_pair(3, &sender);
    generate_election_key_pair(3, &receiver);
    char* json_strung = serialize_election_key_pair(&sender);
    generate_election_partial_key_backup(&sender, &receiver, &backup);
    char* json_strung_backup = serialize_election_partial_key_backup(&backup);
    verify_election_partial_key_backup(&receiver, &sender, &backup, &verification);
    char* json_strung_verification = serialize_election_partial_key_verification(&verification);
    ESP_LOGI(TAG, "Key pair sender: %s", json_strung);
    ESP_LOGI(TAG, "Backup: %s", json_strung_backup);
    ESP_LOGI(TAG, "Verification: %s", json_strung_verification);
    esp_log_level_set("*", ESP_LOG_INFO);
    esp_log_level_set("mqtt_client", ESP_LOG_VERBOSE);
    esp_log_level_set("mqtt_example", ESP_LOG_VERBOSE);
    esp_log_level_set("transport_base", ESP_LOG_VERBOSE);
    esp_log_level_set("esp-tls", ESP_LOG_VERBOSE);
    esp_log_level_set("transport", ESP_LOG_VERBOSE);
    esp_log_level_set("outbox", ESP_LOG_VERBOSE);

    ESP_ERROR_CHECK(nvs_flash_init());
    ESP_ERROR_CHECK(esp_netif_init());
    ESP_ERROR_CHECK(esp_event_loop_create_default());

    /* This helper function configures Wi-Fi or Ethernet, as selected in menuconfig.
     * Read "Establishing Wi-Fi or Ethernet Connection" section in
     * examples/protocols/README.md for more information about this function.
     */
    //ESP_ERROR_CHECK(example_connect());

    // Each guardian connect to broker
    //mqtt_app_start();

}
