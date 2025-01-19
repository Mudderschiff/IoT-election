#include "view.h"

/*********************
 *      DEFINES
 *********************/
#define TAG "GUI"
#define LV_TICK_PERIOD_MS 1

void guiTask(void *pvParameter);


/* Creates a semaphore to handle concurrent call to lvgl stuff
 * If you wish to call *any* lvgl function from other threads/tasks
 * you should lock on the very same semaphore! */
SemaphoreHandle_t xGuiSemaphore;

void guiTask(void *pvParameter) {

    xGuiSemaphore = xSemaphoreCreateMutex();

    lv_init();

    /* Initialize SPI or I2C bus used by the drivers */
    lvgl_driver_init();
    ESP_LOGI(TAG, "OK so far!");

    while(1) {
        vTaskDelay(100 / portTICK_RATE_MS);
    }
}
