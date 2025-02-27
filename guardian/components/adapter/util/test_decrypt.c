#include "test_decrypt.h"

#define MEASUREMENT_RUNS 30

/**
 * @brief Calculates the standard deviation of a given dataset.
 * 
 * @param data Pointer to the array of data points.
 * @param count Number of data points in the array.
 * @return float The standard deviation of the dataset.
 */
static float calculate_std_dev(uint64_t* data, size_t count) {
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

/**
 * @brief Calculates and prints statistical metrics for a given dataset.
 * 
 * @param timings Pointer to the array of timing data points.
 */
static void calculate_statistics(uint64_t* timings) {
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

    printf("\nPerformance Results:\n");
    printf("=====================\n");
    printf("Measurements: %d\n", MEASUREMENT_RUNS);
    printf("Average time: %.2f μs\n", avg);
    printf("Standard deviation: %.2f μs\n", std_dev);
    printf("Minimum time: %llu μs\n", min);
    printf("Maximum time: %llu μs\n", max);
    printf("Variance: %.2f μs²\n", std_dev * std_dev);
}

/**
 * @brief Performs timing measurements for decryption operations and calculates statistics.
 * 
 * @param guardian Pointer to the ElectionKeyPair object used for decryption.
 * @param tally Pointer to the CiphertextTally object to be decrypted.
 */
void perform_measurement(ElectionKeyPair *guardian, CiphertextTally *tally) {
    uint64_t* timings = (uint64_t*)malloc(MEASUREMENT_RUNS * sizeof(uint64_t));
    if(timings == NULL) {
        printf("Failed to allocate memory for timings\n");
        return;
    }

    // Actual measurements
    for (int i = 0; i < MEASUREMENT_RUNS; i++) {
        printf("run: %d\n", i);
        DecryptionShare share;
        uint64_t start = esp_timer_get_time();
        compute_decryption_share(guardian, tally, &share);
        timings[i] = esp_timer_get_time() - start;
        free_DecryptionShare(&share);
        vTaskDelay(pdMS_TO_TICKS(1000));
    }

    calculate_statistics(timings);
    free(timings);
}