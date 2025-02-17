#include "model.h"
#include "adapter.h"
#include "view.h"
#include "serialize.h"
#include "freertos/task.h"
#include "freertos/FreeRTOS.h"
#include "nvs_flash.h"
#include "protocol_examples_common.h"
#include "buff.pb-c.h"
#include "esp_heap_caps.h"
#include "esp_task_wdt.h"
#include "esp_timer.h"
#include <math.h>
#include "sdkconfig.h"
#include "esp_task_wdt.h"

//static const char *TAG = "mqtt_example";

#define WARMUP_RUNS 0

#define MEASUREMENT_RUNS 30
ElectionKeyPair receiver;
ElectionKeyPair sender;
ElectionPartialKeyPairBackup backup;

// Function prototype for the operation you want to test

void target_operation();

// Measurement storage

//uint64_t timings[MEASUREMENT_RUNS];
uint64_t* timings;

float calculate_std_dev(uint64_t* data, size_t count) {
    double sum = 0.0, mean = 0.0, variance = 0.0;
    
    // Calculate mean

    for (size_t i = 0; i < count; i++) {
        sum += data[i];
    }
    mean = sum / count;
    
    // Calculate variance

    for (size_t i = 0; i < count; i++) {
        variance += pow(data[i] - mean, 2);
    }
    variance /= count;
    
    return (float)sqrt(variance);
}

void perform_measurements() {
    // Warmup phase
    timings = (uint64_t*)malloc(MEASUREMENT_RUNS * sizeof(uint64_t));
    if(timings == NULL) {
        printf("Failed to allocate memory for timings\n");
        return;
    }

    // Actual measurements

    for (int i = 0; i < MEASUREMENT_RUNS; i++) {
        printf("run: %d\n", i);
        uint64_t start = esp_timer_get_time();
        target_operation();
        timings[i] = esp_timer_get_time() - start;
        vTaskDelay(pdMS_TO_TICKS(1000));
    }

    // Calculate statistics

    float avg = 0;
    uint64_t min = UINT64_MAX;
    uint64_t max = 0;
    
    for (int i = 0; i < MEASUREMENT_RUNS; i++) {
        avg += timings[i];
        if (timings[i] < min) min = timings[i];
        if (timings[i] > max) max = timings[i];
    }
    avg /= MEASUREMENT_RUNS;
    
    float std_dev = calculate_std_dev(timings, MEASUREMENT_RUNS);

    // Print results

    printf("\nPerformance Results:\n");
    printf("=====================\n");
    printf("Measurements: %d\n", MEASUREMENT_RUNS);
    printf("Average time: %.2f μs\n", avg);
    printf("Standard deviation: %.2f μs\n", std_dev);
    printf("Minimum time: %llu μs\n", min);
    printf("Maximum time: %llu μs\n", max);
    printf("Variance: %.2f μs²\n", std_dev * std_dev);
    free(timings);
}

// Example target function (replace with your actual function)
void target_operation() {
    ElectionPartialKeyVerification verification;
    verify_election_partial_key_backup(&receiver, &sender, &backup, &verification);
    //ElectionPartialKeyPairBackup backup;
    //generate_election_partial_key_backup(&receiver, &sender, &backup);
    //free_ElectionPartialKeyPairBackup(&backup);
}

void app_main(void)
{   
    esp_task_wdt_deinit();
    memset(receiver.guardian_id, 1, sizeof(receiver.guardian_id));
    generate_election_key_pair(3, &receiver);
    memset(sender.guardian_id, 2, sizeof(sender.guardian_id));
    generate_election_key_pair(3, &sender);
    generate_election_partial_key_backup(&receiver, &sender, &backup);
    
    printf("Starting performance measurements...\n");
    
    perform_measurements();
    
    printf("\nMeasurement complete!\n");
    
    // Keep the task alive

    while (1) {
        vTaskDelay(pdMS_TO_TICKS(1000));
    }


}
