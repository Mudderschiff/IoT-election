#ifndef VIEW_H
#define VIEW_H


#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_freertos_hooks.h"
#include "freertos/semphr.h"
#include "esp_system.h"
#include "driver/gpio.h"
#include "esp_log.h"

#include "lvgl.h"
#include "lvgl_helpers.h"



void guiTask(void *pvParameter);

#endif // VIEW_H