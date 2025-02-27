#ifndef TEST_DECRYPT_H
#define TEST_DECRYPT_H
#include "test_decrypt.h"
#include "model.h"
#include "crypto_utils.h"
#include <stdio.h>
#include "esp_timer.h"
#include <math.h>
#include "esp_task_wdt.h"

void perform_measurement(ElectionKeyPair *guardian, CiphertextTally *ciphertally);

#endif // TEST_DECRYPT_H