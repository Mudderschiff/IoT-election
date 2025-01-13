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
    ElectionKeyPair sender;
    ElectionKeyPair receiver;
    ElectionKeyPair *pubkey_map;
    ElectionJointKey joint_key;
    uint8_t sender_id[6] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06};
    uint8_t receiver_id[6] = {0x06, 0x05, 0x04, 0x03, 0x02, 0x01};
    memcpy(sender.guardian_id, sender_id, 6);
    memcpy(receiver.guardian_id, receiver_id, 6);


    generate_election_key_pair(1, &sender);
    generate_election_key_pair(1, &receiver);
    pubkey_map = (ElectionKeyPair*)malloc(2 * sizeof(ElectionKeyPair));
    pubkey_map[0] = sender;
    pubkey_map[1] = receiver;

    combine_election_public_keys(&sender, pubkey_map, 2, &joint_key);
    print_sp_int(joint_key.joint_key);
    print_sp_int(joint_key.commitment_hash);


    // Each guardian connect to broker
    //mqtt_app_start();

}
