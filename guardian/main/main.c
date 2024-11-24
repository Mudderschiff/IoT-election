#include "model.h"
#include "adapter.h"
#include "serialize.h"
#include "freertos/task.h"
#include "freertos/FreeRTOS.h"
#include "nvs_flash.h"
#include "protocol_examples_common.h"
#include "buff.pb-c.h"


static const char *TAG = "mqtt_example";

void app_main(void)
{
    uint8_t mac[6] = {0};
    esp_efuse_mac_get_default(mac);
    ElectionPartialKeyPairBackup backup;
    ElectionPartialKeyVerification verification;
    ElectionKeyPair sender;
    ElectionKeyPair receiver;
    memcpy(sender.guardian_id, mac, 6);
    memcpy(receiver.guardian_id, mac, 6);
    generate_election_key_pair(3, &sender);
    generate_election_key_pair(3, &receiver);
    generate_election_partial_key_backup(&sender, &receiver, &backup);
    verify_election_partial_key_backup(&receiver, &sender, &backup, &verification);
    ESP_LOGI(TAG, "Verification: %d", verification.verified);
    ESP_LOGI(TAG, "Sender");
    print_byte_array(verification.sender, 6);
    ESP_LOGI(TAG, "Receiver");
    print_byte_array(verification.receiver, 6);
    unsigned len;
    uint8_t* buffer = serialize_election_partial_key_verification(&verification, &len);
    print_byte_array(buffer, len);
    ElectionPartialKeyVerification verification2;
    deserialize_election_partial_key_verification(buffer, len, &verification2);
    ESP_LOGI(TAG, "Verification: %d", verification2.verified);
    ESP_LOGI(TAG, "Sender");
    print_byte_array(verification2.sender, 6);
    ESP_LOGI(TAG, "Receiver");
    print_byte_array(verification2.receiver, 6);

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
