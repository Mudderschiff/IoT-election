#ifndef TEST_PERFORMANCE_H
#define TEST_PERFORMANCE_H
#include "test_performance.h"
#include "model.h"
#include "crypto_utils.h"
#include "freertos/task.h"
#include "freertos/FreeRTOS.h"
#include "esp_task_wdt.h"
#include "esp_timer.h"
#include <math.h>
#include "sdkconfig.h"
#include "esp_task_wdt.h"

void perform_measurements_keygen(int quorum);
void perform_measurements_backup();
void perform_measurements_verification();

#endif // TEST_PERFORMANCE_H