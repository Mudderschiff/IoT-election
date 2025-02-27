#include "test_performance.h"

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
 * @brief Performs timing measurements for election key pair generation and calculates statistics.
 * 
 * @param quorum The quorum size used for key generation.
 */
void perform_measurements_keygen(int quorum) {
    uint64_t* timings = (uint64_t*)malloc(MEASUREMENT_RUNS * sizeof(uint64_t));
    if(timings == NULL) {
        printf("Failed to allocate memory for timings\n");
        return;
    }

    // Actual measurements
    for (int i = 0; i < MEASUREMENT_RUNS; i++) {
        printf("run: %d\n", i);
        ElectionKeyPair sender;
        memset(&sender.guardian_id, 1, sizeof(sender.guardian_id));

        uint64_t start = esp_timer_get_time();
        generate_election_key_pair(quorum, &sender);
        timings[i] = esp_timer_get_time() - start;

        free_ElectionKeyPair(&sender);
        vTaskDelay(pdMS_TO_TICKS(1000));
    }

    calculate_statistics(timings);
    free(timings);
}

/**
 * @brief Performs timing measurements for election partial key backup generation and calculates statistics.
 */
void perform_measurements_backup() {
    ElectionKeyPair sender;
    memset(&sender.guardian_id, 1, sizeof(sender.guardian_id));
    generate_election_key_pair(3, &sender);
    ElectionKeyPair receiver;
    memset(&receiver.guardian_id, 2, sizeof(receiver.guardian_id));
    generate_election_key_pair(3, &receiver);
    uint64_t* timings = (uint64_t*)malloc(MEASUREMENT_RUNS * sizeof(uint64_t));
    if(timings == NULL) {
        printf("Failed to allocate memory for timings\n");
        return;
    }

    // Actual measurements
    for (int i = 0; i < MEASUREMENT_RUNS; i++) {
        printf("run: %d\n", i);
        ElectionPartialKeyPairBackup backup;
        uint64_t start = esp_timer_get_time();
        generate_election_partial_key_backup(&receiver, &sender, &backup);
        timings[i] = esp_timer_get_time() - start;
        free_ElectionPartialKeyPairBackup(&backup);
        vTaskDelay(pdMS_TO_TICKS(1000));
    }

    calculate_statistics(timings);

    free_ElectionKeyPair(&sender);
    free_ElectionKeyPair(&receiver);
    free(timings);
}

/**
 * @brief Performs timing measurements for election partial key backup verification and calculates statistics.
 */
void perform_measurements_verification() {
    ElectionKeyPair sender;
    memset(&sender.guardian_id, 1, sizeof(sender.guardian_id));
    generate_election_key_pair(3, &sender);
    ElectionKeyPair receiver;
    memset(&receiver.guardian_id, 2, sizeof(receiver.guardian_id));
    generate_election_key_pair(3, &receiver);
    ElectionPartialKeyPairBackup backup;
    generate_election_partial_key_backup(&sender, &receiver, &backup);

    uint64_t* timings = (uint64_t*)malloc(MEASUREMENT_RUNS * sizeof(uint64_t));
    if(timings == NULL) {
        printf("Failed to allocate memory for timings\n");
        return;
    }

    // Actual measurements
    for (int i = 0; i < MEASUREMENT_RUNS; i++) {
        printf("run: %d\n", i);
        ElectionPartialKeyVerification verification;

        uint64_t start = esp_timer_get_time();
        verify_election_partial_key_backup(&receiver, &sender, &backup, &verification);
        timings[i] = esp_timer_get_time() - start;

        vTaskDelay(pdMS_TO_TICKS(1000));
    }

    calculate_statistics(timings);

    free_ElectionKeyPair(&sender);
    free_ElectionKeyPair(&receiver);
    free_ElectionPartialKeyPairBackup(&backup);
    free(timings);
}
