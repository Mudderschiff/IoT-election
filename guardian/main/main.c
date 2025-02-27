#include "adapter.h"
#include "nvs_flash.h"
#include "test_performance.h"
#include "esp_task_wdt.h"

static void run_test() {
    esp_task_wdt_deinit();
    printf("Starting performance measurements, Keygen_Q3\n");
    perform_measurements_keygen(3);
    
    //printf("Starting performance measurements, Keygen_Q4\n");
    //perform_measurements_keygen(4);
    
    //printf("Starting performance measurements, Keygen_Q5\n");
    //perform_measurements_keygen(5);
    
    //printf("Starting performance measurements, Keygen_Q6\n");
    //perform_measurements_keygen(6);
    
    //printf("Starting performance measurements, Backup generation\n");
    //perform_measurements_backup();
    
    //printf("Starting performance measurements, Verification\n");
    //perform_measurements_verification();
    while (1) {
        vTaskDelay(pdMS_TO_TICKS(1000));
    }
}

static void guardian_client() {
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
    ESP_ERROR_CHECK(example_connect());

    //Start the MQTT client
    mqtt_app_start();
}

void app_main(void)
{   
    esp_task_wdt_deinit();
    guardian_client();

    // Performance Test
    //run_test();
}
