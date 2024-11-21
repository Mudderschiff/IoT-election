#include "adapter.h"

static const char *TAG = "mqtt_example";
static char client_id[64];
static int sequence_order = -1;


void log_error_if_nonzero(const char *message, int error_code)
{
    if (error_code != 0)
    {
        ESP_LOGE(TAG, "Last error %s: 0x%x", message, error_code);
    }
}

/*
 * @brief Event handler registered to receive MQTT events
 *
 *  This function is called by the MQTT client event loop.
 *
 * @param handler_args user data registered to the event.
 * @param base Event base for the handler(always MQTT Base in this example).
 * @param event_id The id for the received event.
 * @param event_data The data for the event, esp_mqtt_event_handle_t.
 */
void mqtt_event_handler(void *handler_args, esp_event_base_t base, int32_t event_id, void *event_data)
{
    ESP_LOGD(TAG, "Event dispatched from event loop base=%s, event_id=%" PRIi32 "", base, event_id);
    esp_mqtt_event_handle_t event = event_data;
    esp_mqtt_client_handle_t client = event->client;
    int msg_id;
    switch ((esp_mqtt_event_id_t)event_id)
    {
    case MQTT_EVENT_CONNECTED:
        char topic[256];
        snprintf(topic, sizeof(topic), "clients/%s/register", client_id);
        msg_id = esp_mqtt_client_publish(client, topic, "true", 0, 2, 1);
        ESP_LOGI(TAG, "sent publish successful, topic=%s, msg_id=%d", topic, msg_id);
        
        snprintf(topic, sizeof(topic), "clients/%s/sequence_order", client_id);
        msg_id = esp_mqtt_client_subscribe(client, topic, 2);
        ESP_LOGI(TAG, "sent subscribe successful, topic=%s, msg_id=%d", topic, msg_id);
        break;
    case MQTT_EVENT_DISCONNECTED:
        ESP_LOGI(TAG, "MQTT_EVENT_DISCONNECTED");
        break;
    case MQTT_EVENT_SUBSCRIBED:
        ESP_LOGI(TAG, "MQTT_EVENT_SUBSCRIBED, msg_id=%d", event->msg_id);
        break;
    case MQTT_EVENT_UNSUBSCRIBED:
        ESP_LOGI(TAG, "MQTT_EVENT_UNSUBSCRIBED, msg_id=%d", event->msg_id);
        break;
    case MQTT_EVENT_PUBLISHED:
        ESP_LOGI(TAG, "MQTT_EVENT_PUBLISHED, msg_id=%d", event->msg_id);
        break;
    case MQTT_EVENT_DATA:
        ESP_LOGI(TAG, "MQTT_EVENT_DATA");
        ESP_LOGI(TAG, "TOPIC=%.*s", event->topic_len, event->topic);
        ESP_LOGI(TAG, "DATA=%.*s", event->data_len, event->data);
        char expected_prefix[256];
        snprintf(expected_prefix, sizeof(expected_prefix), "clients/%s", client_id);
        if (strncmp(event->topic, expected_prefix, strlen(expected_prefix)) == 0 &&
        strstr(event->topic, "/sequence_order") != NULL)
        {
            cJSON *json = cJSON_Parse(event->data);
            if (json == NULL)
            {
                ESP_LOGE(TAG, "Failed to parse JSON");
                break;
            }

            cJSON *sequence_order_item = cJSON_GetObjectItem(json, "sequence_order");
            if (cJSON_IsNumber(sequence_order_item))
            {
                sequence_order = sequence_order_item->valueint;
                ESP_LOGI(TAG, "Sequence Order: %d", sequence_order);
            }
            else
            {
                ESP_LOGE(TAG, "sequence_order not found or not a number");
            }
        }
        break;
    case MQTT_EVENT_ERROR:
        ESP_LOGI(TAG, "MQTT_EVENT_ERROR");
        if (event->error_handle->error_type == MQTT_ERROR_TYPE_TCP_TRANSPORT)
        {
            log_error_if_nonzero("reported from esp-tls", event->error_handle->esp_tls_last_esp_err);
            log_error_if_nonzero("reported from tls stack", event->error_handle->esp_tls_stack_err);
            log_error_if_nonzero("captured as transport's socket errno", event->error_handle->esp_transport_sock_errno);
            ESP_LOGI(TAG, "Last errno string (%s)", strerror(event->error_handle->esp_transport_sock_errno));
        }
        break;
    default:
        ESP_LOGI(TAG, "Other event id:%d", event->event_id);
        break;
    }
}

void mqtt_publish_public_key(void)
{
    // Publish public key to a specific topic

}

void mqtt_subscribe_public_key(void)
{
    // Subscribe to a specific topic to receive public keys from other guardians
}


void mqtt_app_start(void)
{
    uint8_t mac[6] = {0};
    esp_efuse_mac_get_default(mac);
    snprintf(client_id, sizeof(client_id), "ESP_%02x%02x%02x", mac[3], mac[4], mac[5]);
    ESP_LOGI(TAG, "Client ID: %s", client_id);

    esp_mqtt_client_config_t mqtt_cfg = {
        .broker.address.uri = "mqtt://192.168.12.1:1883",
    };
    esp_mqtt_client_handle_t client = esp_mqtt_client_init(&mqtt_cfg);
    /* The last argument may be used to pass data to the event handler, in this example mqtt_event_handler */
    esp_mqtt_client_register_event(client, ESP_EVENT_ANY_ID, mqtt_event_handler, NULL);
    esp_mqtt_client_start(client);

    // Round 1
    // Each guardian publishes it"s public key to a specific topic
    // esp_mqtt_client_publish(client, "/topic/public_keys", public_key, 0, 2, 1);

    // Each guardian subscribes to the topic to receive the public keys from other guardians
    //Guardians exchange all public keys and ensure each fellow guardian has received an election public key ensuring at all guardians are in attendance.

    //const char *public_key = "public_key";
    //esp_mqtt_client_publish(client, "/topic/public_keys", public_key, 0, 2, 1);

    //esp_mqtt_client_subscribe(client, "/topic/public_keys", 2);
    
    //Round 2
    //Each guardian generates partial key backups and publishes them to designated topics
    //Each guardian verifies the received partial key backups and publishes verification results
    //Guardians generate a partial key backup for each guardian and share with that designated key with that guardian. Then each designated guardian sends a verification back to the sender. The sender then publishes to the group when all verifications are received.
    //Each guardian must generate election partial key backup for each other guardian. The guardian will use their polynomial and the designated guardian's sequence_order to create the value.

    //Round 3
    //The final step is to publish the joint election key after all keys and backups have been shared.
}
