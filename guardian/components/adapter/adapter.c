#include "adapter.h"

static const char *TAG = "Adapter";
uint8_t mac[6] = {0};
int quorum = 0;
int max_guardians = 0;

int key_pair_count = 0;
int backup_count = 0;
int verification_count = 0;

ElectionKeyPair *key_pair_map;
ElectionPartialKeyPairBackup *backup_map;
ElectionPartialKeyVerification *verification_map;

void handle_ceremony_details(esp_mqtt_client_handle_t client, const char *data, int data_len);
void handle_public_key(esp_mqtt_client_handle_t client, const char *data, int data_len);
void handle_backup(esp_mqtt_client_handle_t client, const char *data, int data_len);
void handle_verification(esp_mqtt_client_handle_t client, const char *data, int data_len);

void add_key_pair(ElectionKeyPair *key_pair);
ElectionKeyPair* find_key_pair(uint8_t *guardian_id);
void delete_key_pair(uint8_t *guardian_id);
void add_backup(ElectionPartialKeyPairBackup *backup);
ElectionPartialKeyPairBackup* find_backup(uint8_t *sender_id, uint8_t *receiver_id);
void delete_backup(uint8_t *sender_id, uint8_t *receiver_id);
void add_verification(ElectionPartialKeyVerification *verification);
ElectionPartialKeyVerification* find_verification(uint8_t *sender_id, uint8_t *receiver_id, uint8_t *verifier);
void delete_verification(uint8_t *sender_id, uint8_t *receiver_id, uint8_t *verifier);


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
        //memcpy(guardian.guardian_id, mac, 6);
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
            //handle_backup(client, event->data, event->data_len);
        }
        else if(strncmp(topic, "verifications", event->topic_len) == 0)
        {
            ESP_LOGI(TAG, "Received Verification");
            //handle_verification(client, event->data, event->data_len);
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
    ElectionKeyPair guardian;
    memcpy(guardian.guardian_id, mac, 6);

    key_pair_map = malloc(max_guardians * sizeof(ElectionKeyPair));
    backup_map = malloc(max_guardians * max_guardians * sizeof(ElectionPartialKeyPairBackup));
    verification_map = malloc(max_guardians * max_guardians * max_guardians * sizeof(ElectionPartialKeyVerification));

    ESP_LOGI(TAG, "Quorum: %d, Max Guardians: %d", quorum, max_guardians);


    generate_election_key_pair(quorum, &guardian);
    add_key_pair(&guardian);
    
    buffer = serialize_election_key_pair(&guardian, &len);

    esp_mqtt_client_publish(client, "pub_keys", buffer, len, 2, 0);
    ESP_LOGI(TAG, "Sent Public Key");
    free(buffer);
    free_ElectionKeyPair(&guardian);
}

void handle_public_key(esp_mqtt_client_handle_t client, const char *data, int data_len)
{
    ElectionKeyPair sender;
    ElectionPartialKeyPairBackup backup;
    deserialize_election_key_pair((uint8_t*)data, data_len, &sender);

    ElectionKeyPair *entry = find_key_pair(sender.guardian_id);
    if(entry == NULL) {
        add_key_pair(&sender);
    }
    ElectionKeyPair *own_entry = find_key_pair(mac);

    ElectionPartialKeyPairBackup *backup_entry = find_backup(sender.guardian_id, own_entry->guardian_id); ;
    if(backup_entry == NULL)
    {
        generate_election_partial_key_backup(own_entry, &sender, &backup);
        add_backup(&backup);
        void *buffer;
        size_t len;
        buffer = serialize_election_partial_key_backup(&backup, &len);
        esp_mqtt_client_publish(client, "backups", buffer, len, 2, 0);
        ESP_LOGI(TAG, "Sent backup");
        free(buffer);
    }
    else
    {
        ESP_LOGI(TAG, "Backup already exists");
    }
}

void handle_backup(esp_mqtt_client_handle_t client, const char *data, int data_len)
{
    ElectionPartialKeyPairBackup backup;
    ElectionPartialKeyVerification verification;
    deserialize_election_partial_key_backup((uint8_t*)data, data_len, &backup);

    /*
    if(memcmp(backup.receiver, guardian.guardian_id, 6) == 0)
    {
        ESP_LOGI(TAG, "Received backup from designated guardian");
        //verify_election_partial_key_backup(&guardian, &backup, &verification);
        //verify_election_partial_key_backup(&receiver, &sender, &backup, &verification);


        void *buffer;
        size_t len;
        buffer = serialize_election_partial_key_verification(&verification, &len);
        esp_mqtt_client_publish(client, "verifications", buffer, len, 2, 0);
        ESP_LOGI(TAG, "Sent verification");
        free(buffer);
    }
    else
    {
        ESP_LOGI(TAG, "Received backup from another guardian");
        //verify backup
    }
    */
    
}

void handle_verification(esp_mqtt_client_handle_t client, const char *data, int data_len)
{
    // Parse the data and store the verification
}


// Function to add an entry to the key pair map
void add_key_pair(ElectionKeyPair *key_pair) {
    if (key_pair_count < max_guardians) {
        key_pair_map[key_pair_count] = *key_pair;
        key_pair_count++;
    } else {
        printf("Key pair map is full\n");
    }
}

// Function to find an entry in the key pair map
ElectionKeyPair* find_key_pair(uint8_t *guardian_id) {
    for (int i = 0; i < key_pair_count; i++) {
        if (memcmp(key_pair_map[i].guardian_id, guardian_id, 6) == 0) {
            return &key_pair_map[i];
        }
    }
    return NULL;
}

// Function to delete an entry from the key pair map
void delete_key_pair(uint8_t *guardian_id) {
    for (int i = 0; i < key_pair_count; i++) {
        if (memcmp(key_pair_map[i].guardian_id, guardian_id, 6) == 0) {
            free_ElectionKeyPair(&key_pair_map[i]);
            // Shift remaining elements to the left
            for (int j = i; j < key_pair_count - 1; j++) {
                key_pair_map[j] = key_pair_map[j + 1];
            }
            key_pair_count--;
            return;
        }
    }
    printf("Guardian ID not found\n");
}

// Similar functions can be implemented for the backup and verification maps
void add_backup(ElectionPartialKeyPairBackup *backup) {
    ElectionPartialKeyPairBackup *existing_backup = find_backup(backup->sender, backup->receiver);
    if(existing_backup == NULL) {
        if (backup_count < max_guardians * max_guardians) {
            backup_map[backup_count++] = *backup;
        } else {
            printf("Backup map is full\n");
        }
    } else {
        *existing_backup = *backup;
    }
}

ElectionPartialKeyPairBackup* find_backup(uint8_t *sender_id, uint8_t *receiver_id) {
    for (int i = 0; i < backup_count; i++) {
        if (memcmp(backup_map[i].sender, sender_id, 6) == 0 &&
            memcmp(backup_map[i].receiver, receiver_id, 6) == 0) {
            return &backup_map[i];
        }
    }
    return NULL;
}

void delete_backup(uint8_t *sender_id, uint8_t *receiver_id) {
    ElectionPartialKeyPairBackup *backup = find_backup(sender_id, receiver_id);
    if (backup != NULL) {
        int index = backup - backup_map;
        memmove(&backup_map[index], &backup_map[index + 1], (backup_count - index - 1) * sizeof(ElectionPartialKeyPairBackup));
        backup_count--;
    }
}

void add_verification(ElectionPartialKeyVerification *verification) {
    ElectionPartialKeyVerification *existing_verification = find_verification(verification->sender, verification->receiver, verification->verifier);
    if (existing_verification == NULL) {
        if(backup_count < max_guardians) {
            verification_map[verification_count] = *verification;
            verification_count++;
        } else {
            printf("Verification map is full\n");
        }
    } else {
        *existing_verification = *verification;
    }
}


ElectionPartialKeyVerification* find_verification(uint8_t *sender_id, uint8_t *receiver_id, uint8_t *verifier) {
    for (int i = 0; i < verification_count; i++) {
        if (memcmp(verification_map[i].sender, sender_id, 6) == 0 && 
            memcmp(verification_map[i].receiver, receiver_id, 6) == 0 && 
            memcmp(verification_map[i].verifier, verifier, 6) == 0) {
            return &verification_map[i];
        }
    }
    return NULL;
}


void delete_verification(uint8_t *sender_id, uint8_t *receiver_id, uint8_t *verifier) {
    ElectionPartialKeyVerification *verification = find_verification(sender_id, receiver_id, verifier);
    if (verification != NULL) {
        int index = verification - verification_map;
        memmove(&verification_map[index], &verification_map[index + 1], (verification_count - index - 1) * sizeof(ElectionPartialKeyVerification));
        verification_count--;
    }
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
