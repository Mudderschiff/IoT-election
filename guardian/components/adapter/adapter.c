#include "adapter.h"

static const char *TAG = "Adapter";
uint8_t mac[6] = {0};
int quorum = 0;
int max_guardians = 0;

ElectionKeyPair guardian;

void handle_ceremony_details(esp_mqtt_client_handle_t client, const char *data, int data_len);
void handle_public_key(esp_mqtt_client_handle_t client, const char *data, int data_len);
void handle_backup(const char *data, int data_len);
void handle_verification(const char *data, int data_len);

void publish_to_pub_key(esp_mqtt_client_handle_t client, const char *data);
void publish_to_backups(esp_mqtt_client_handle_t client, const char *data);
void publish_to_verifications(esp_mqtt_client_handle_t client, const char *data);


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
    case MQTT_EVENT_BEFORE_CONNECT:
        ESP_LOGI(TAG, "MQTT_EVENT_BEFORE_CONNECT");
        // Get the MAC address of the device and set it as the guardian_id
        esp_efuse_mac_get_default(mac);
        memcpy(guardian.guardian_id, mac, 6);
        break;
    case MQTT_EVENT_CONNECTED:
        msg_id = esp_mqtt_client_subscribe(client, "ceremony_details", 1);
        ESP_LOGI(TAG, "sent subscribe successful, msg_id=%d", msg_id);
        msg_id = esp_mqtt_client_subscribe(client, "pub_keys", 1);
        ESP_LOGI(TAG, "sent subscribe successful, msg_id=%d", msg_id);
        msg_id = esp_mqtt_client_subscribe(client, "backups", 1);
        ESP_LOGI(TAG, "sent subscribe successful, msg_id=%d", msg_id);
        msg_id = esp_mqtt_client_subscribe(client, "verifications", 1); 
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
        char topic[50];
        snprintf(topic, event->topic_len + 1, "%.*s", event->topic_len, event->topic);
        ESP_LOGI(TAG, "Topic: %s", topic);
        if(strncmp(topic, "ceremony_details", event->topic_len) == 0)
        {
            if(sscanf(event->data, "%d,%d", &quorum, &max_guardians) == 2) {
                ESP_LOGI(TAG, "Received Ceremony Details");
                handle_ceremony_details(client, event->data, event->data_len);
            }
        }
        else if(strncmp(topic, "pub_keys", event->topic_len) == 0)
        {
            ESP_LOGI(TAG, "Received Public Key");
            handle_public_key(client, event->data, event->data_len);
        }
        else if(strncmp(topic, "backups", event->topic_len) == 0)
        {
            ESP_LOGI(TAG, "Received Backup");
            handle_backup(event->data, event->data_len);
        }
        else if(strncmp(topic, "verifications", event->topic_len) == 0)
        {
            handle_verification(event->data, event->data_len);
        } else {
            ESP_LOGI(TAG, "Unknown topic");
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

void handle_ceremony_details(esp_mqtt_client_handle_t client, const char *data, int data_len)
{
    void *buffer;
    size_t len;
    ESP_LOGI(TAG, "Quorum: %d, Max Guardians: %d", quorum, max_guardians);
    generate_election_key_pair(quorum, &guardian);
    buffer = serialize_election_key_pair(&guardian, &len);
    esp_mqtt_client_publish(client, "pub_keys", buffer, len, 2, 0);
    ESP_LOGI(TAG, "Sent Public Key");
    free(buffer);
}

void handle_public_key(esp_mqtt_client_handle_t client, const char *data, int data_len)
{
    ElectionKeyPair sender;
    ElectionPartialKeyPairBackup backup;
    deserialize_election_key_pair((uint8_t*)data, data_len, &sender);

    if(memcmp(sender.guardian_id, guardian.guardian_id, 6) == 0)
    {
        ESP_LOGI(TAG, "Received own public key");
        //void *buffer;
        //size_t len;
        //vTaskDelay(1000 / portTICK_PERIOD_MS);
        //generate_election_partial_key_backup(&guardian, &sender, &backup);
        //buffer = serialize_election_partial_key_backup(&backup, &len);
        //esp_mqtt_client_publish(client, "backups", buffer, len, 2, 0);
        //ESP_LOGI(TAG, "Sent backup");
        //free(buffer);

    }
    else
    {
        ESP_LOGI(TAG, "Received public key from another guardian");
        //generate backup
    }

    free_ElectionKeyPair(&sender);
}

void handle_backup(const char *data, int data_len)
{
    // Parse the data and store the backup
}

void handle_verification(const char *data, int data_len)
{
    // Parse the data and store the verification
}

void publish_to_pub_key(esp_mqtt_client_handle_t client, const char *data)
{

    esp_mqtt_client_publish(client, "pub_key", data, 0, 2, 1);
}

void publish_to_backups(esp_mqtt_client_handle_t client, const char *data)
{
    esp_mqtt_client_publish(client, "backups", data, 0, 2, 1);
}

void publish_to_verifications(esp_mqtt_client_handle_t client, const char *data)
{
    esp_mqtt_client_publish(client, "verifications", data, 0, 2, 1);
}



void mqtt_app_start(void)
{
    esp_mqtt_client_config_t mqtt_cfg = {
        .broker.address.uri = "mqtt://192.168.12.1:1883",
        .session.last_will = {
            .topic = "guardian_status",
            .qos = 2,
            .retain = 1,
            .msg = "Guardian has disconnected",
        },
        .buffer.size = 4096,
    };
    esp_mqtt_client_handle_t client = esp_mqtt_client_init(&mqtt_cfg);
    /* The last argument may be used to pass data to the event handler, in this example mqtt_event_handler */
    esp_mqtt_client_register_event(client, ESP_EVENT_ANY_ID, mqtt_event_handler, NULL);
    esp_mqtt_client_start(client);

    
    //Round 2
    //Each guardian generates partial key backups and publishes them to designated topics
    //Each guardian verifies the received partial key backups and publishes verification results
    //Guardians generate a partial key backup for each guardian and share with that designated key with that guardian. Then each designated guardian sends a verification back to the sender. The sender then publishes to the group when all verifications are received.
    //Each guardian must generate election partial key backup for each other guardian. The guardian will use their polynomial and the designated guardian's sequence_order to create the value.

    //Round 3
    //The final step is to publish the joint election key after all keys and backups have been shared.
}
