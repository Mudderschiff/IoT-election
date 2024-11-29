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
    ElectionKeyPair sender;
    memcpy(sender.guardian_id, mac, 6);
    generate_election_key_pair(3, &sender);
    
    ESP_LOGI("ElectionKeyPair", "Generated Election Key Pair");
    print_sp_int(sender.public_key);
    print_sp_int(sender.polynomial.coefficients[0].value);
    print_sp_int(sender.polynomial.coefficients[0].commitment);
    print_sp_int(sender.polynomial.coefficients[0].proof.pubkey);
    print_sp_int(sender.polynomial.coefficients[0].proof.commitment);
    print_sp_int(sender.polynomial.coefficients[0].proof.challenge);
    print_sp_int(sender.polynomial.coefficients[0].proof.response);

    unsigned len;
    ElectionKeyPair sender2;

    uint8_t* buffer = serialize_election_key_pair(&sender, &len);
    print_byte_array(buffer, len);
    
    /*
    deserialize_election_key_pair(buffer, len, &sender2);
    ESP_LOGI("ElectionKeyPair", "Deserialized Election Key Pair");
    print_sp_int(sender2.public_key);
    print_sp_int(sender2.polynomial.coefficients[0].value);
    print_sp_int(sender2.polynomial.coefficients[0].commitment);
    print_sp_int(sender2.polynomial.coefficients[0].proof.pubkey);
    print_sp_int(sender2.polynomial.coefficients[0].proof.commitment);
    print_sp_int(sender2.polynomial.coefficients[0].proof.challenge);
    print_sp_int(sender2.polynomial.coefficients[0].proof.response);

    */

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
