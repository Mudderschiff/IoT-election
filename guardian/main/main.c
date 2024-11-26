#include "model.h"
#include "adapter.h"
#include "serialize.h"
#include "freertos/task.h"
#include "freertos/FreeRTOS.h"
#include "nvs_flash.h"
#include "protocol_examples_common.h"
#include "buff.pb-c.h"
#include "esp_heap_caps.h"
#include "esp_task_wdt.h"

static const char *TAG = "mqtt_example";

void app_main(void)
{   
    uint8_t mac[6] = {0};
    esp_efuse_mac_get_default(mac);
    ElectionPartialKeyPairBackup backup;
    //ElectionPartialKeyVerification verification;
    ElectionKeyPair sender;
    ElectionKeyPair receiver;
    memcpy(sender.guardian_id, mac, 6);
    memcpy(receiver.guardian_id, mac, 6);
    generate_election_key_pair(3, &sender);
    generate_election_key_pair(3, &receiver);

    vTaskDelay(1000 / portTICK_PERIOD_MS);
    generate_election_partial_key_backup(&sender, &receiver, &backup);
    


    //vTaskDelay(1000 / portTICK_PERIOD_MS);
    //verify_election_partial_key_backup(&receiver, &sender, &backup, &verification);
    //ESP_LOGI(TAG, "Verification verified: %d", verification.verified);
    //ESP_LOGI(TAG, "Backup encrypted_coordinate.pad");
    //print_sp_int(backup.encrypted_coordinate.pad);
    //ESP_LOGI(TAG, "Backup encrypted_coordinate.data");
    //print_sp_int(backup.encrypted_coordinate.data);
    //ESP_LOGI(TAG, "Backup encrypted_coordinate.mac");
    //print_sp_int(backup.encrypted_coordinate.mac);
    //heap_caps_print_heap_info(MALLOC_CAP_DEFAULT);

    //unsigned len;
    //uint8_t* buffer = serialize_election_partial_key_verification(&verification, &len);
    
    //uint8_t* buffer = serialize_election_partial_key_verification(&verification, &len);
    //uint8_t* buffer = serialize_election_partial_key_backup(&backup, &len);

    //ElectionPartialKeyPairBackup backup2;
    //deserialize_election_partial_key_backup(buffer, len, &backup2);
    //ESP_LOGI(TAG, "Deserialised Backup receiver");
    //ESP_LOGI(TAG, "Deserialised Backup encrypted_coordinate.pad");
    //print_sp_int(backup2.encrypted_coordinate.pad);
    //ESP_LOGI(TAG, "Deserialised Backup encrypted_coordinate.data");
    //print_sp_int(backup2.encrypted_coordinate.data);
    //ESP_LOGI(TAG, "Deserialised Backup encrypted_coordinate.mac");
    //print_sp_int(backup2.encrypted_coordinate.mac);

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
