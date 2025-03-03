#include "adapter.h"

static const char *TAG = "Adapter";
uint8_t mac[6] = {0};

int pubkey_count = 0;
int backup_count = 0;
int max_guardians = 0;
int quorum;

ElectionKeyPair guardian;
ElectionKeyPair *pubkey_map;
ElectionPartialKeyPairBackup *backup_map;

static void verify_backups(esp_mqtt_client_handle_t client);
static void generate_backups(esp_mqtt_client_handle_t client);
static void publish_public_key(esp_mqtt_client_handle_t client, const char *data, int data_len);
static void handle_pubkeys(esp_mqtt_client_handle_t client, const char *data, int data_len);
static void handle_backups(esp_mqtt_client_handle_t client, const char *data, int data_len);
static void handle_challenge(esp_mqtt_client_handle_t client, const char *data, int data_len);
static void handle_ciphertext_tally(esp_mqtt_client_handle_t client, const char *data, int data_len);

// Helper functions to manage the pubkey and backup maps
static void add_key_pair(ElectionKeyPair *key_pair);
static ElectionKeyPair* find_key_pair(uint8_t *guardian_id);
static void delete_key_pair(uint8_t *guardian_id);
static void add_backup(ElectionPartialKeyPairBackup *backup);
static ElectionPartialKeyPairBackup* find_backup(uint8_t *guardian_id);
static void delete_backup(uint8_t *guardian_id);

// Log an error message if the error code is non-zero
static void log_error_if_nonzero(const char *message, int error_code)
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
    //int msg_id;
    switch ((esp_mqtt_event_id_t)event_id)
    {
    case MQTT_EVENT_BEFORE_CONNECT:
        ESP_LOGI(TAG, "MQTT_EVENT_BEFORE_CONNECT");
        // Get the MAC address of the device and set it as the guardian_id
        esp_efuse_mac_get_default(mac);
        memcpy(guardian.guardian_id, mac, 6);
        break;
    case MQTT_EVENT_CONNECTED:
        esp_mqtt_client_subscribe(client, "ceremony_details", 1);
        break;
    case MQTT_EVENT_DISCONNECTED:
        ESP_LOGI(TAG, "MQTT_EVENT_DISCONNECTED");
        esp_mqtt_client_unsubscribe(client, "ceremony_details");
        esp_mqtt_client_unsubscribe(client, "pub_keys");
        esp_mqtt_client_unsubscribe(client, "backups");
        esp_mqtt_client_unsubscribe(client, "challenge");
        esp_mqtt_client_unsubscribe(client, "ciphertally");
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
        char topic[20];
        snprintf(topic, event->topic_len + 1, "%.*s", event->topic_len, event->topic);
        ESP_LOGI(TAG, "Topic: %s", topic);
        if(strncmp(topic, "ceremony_details", event->topic_len) == 0)
        {
            if(sscanf(event->data, "%d,%d", &quorum, &max_guardians) == 2) {
                ESP_LOGI(TAG, "Received Ceremony Details");
                ESP_LOGI(TAG, "Quorum: %d, Max Guardians: %d", quorum, max_guardians);
                // Exclude self from guardian count
                max_guardians--;
                ESP_LOGI(TAG, "Max Guardians: %d", max_guardians);
                pubkey_map = (ElectionKeyPair*)malloc(max_guardians * sizeof(ElectionKeyPair));
                backup_map = (ElectionPartialKeyPairBackup*)malloc(max_guardians * sizeof(ElectionPartialKeyPairBackup));
                esp_mqtt_client_unsubscribe(client, "ceremony_details");
                esp_mqtt_client_subscribe(client, "pub_keys", 1);
                esp_mqtt_client_subscribe(client, "backups", 1);
                esp_mqtt_client_subscribe(client, "challenge", 1);
                publish_public_key(client, event->data, event->data_len);
            }
        }
        else if(strncmp(topic, "pub_keys", event->topic_len) == 0)
        {
            ESP_LOGI(TAG, "Received Public Key");
            handle_pubkeys(client, event->data, event->data_len);
        }
        else if(strncmp(topic, "backups", event->topic_len) == 0)
        {
            ESP_LOGI(TAG, "Received Backup");
            handle_backups(client, event->data, event->data_len);
        }
        else if(strncmp(topic, "challenge", event->topic_len) == 0)
        {
            ESP_LOGI(TAG, "Received Challenge");
            handle_challenge(client, event->data, event->data_len);
        } 
        else if (strncmp(topic, "ciphertally", event->topic_len) == 0)
        {
            ESP_LOGI(TAG, "Received ciphertext tally");
            handle_ciphertext_tally(client, event->data, event->data_len);
        }
        else {
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

// Verify the received backups. If all backups are verified, combine the public keys and publish the joint key.
static void verify_backups(esp_mqtt_client_handle_t client) {
    bool all_verified = true;
    ElectionPartialKeyVerification verification;
    void *buffer;
    size_t len;
    for (int i = 0; i < max_guardians; i++) {
        ElectionPartialKeyPairBackup *backup = &backup_map[i];
        verify_election_partial_key_backup(&guardian, find_key_pair(backup->sender), backup, &verification);
        if(verification.verified == 0)
        {
            // send challenge
            buffer = serialize_election_partial_key_verification(&verification, &len);
            esp_mqtt_client_enqueue(client, "challenge", buffer, len, 2, 0, false);
            free(buffer);
            all_verified = false;
        }
    }
    if(all_verified)
    {
        ElectionJointKey joint_key;
        combine_election_public_keys(&guardian, pubkey_map, pubkey_count, &joint_key); 
        int size = sp_unsigned_bin_size(joint_key.joint_key) + sp_unsigned_bin_size(joint_key.commitment_hash);
        byte *buffer = malloc(size);
        sp_to_unsigned_bin(joint_key.joint_key, buffer);
        sp_to_unsigned_bin_at_pos(sp_unsigned_bin_size(joint_key.joint_key), joint_key.commitment_hash, buffer);

        esp_mqtt_client_enqueue(client, "joint_key", (char*)buffer, size, 1, 0, false);
        esp_mqtt_client_subscribe(client, "ciphertally", 2);
        FREE_MP_INT_SIZE(joint_key.joint_key, NULL, DYNAMIC_TYPE_BIGINT);
        FREE_MP_INT_SIZE(joint_key.commitment_hash, NULL, DYNAMIC_TYPE_BIGINT);
        free(buffer);
    }

}

// Generate a backup for each received public key and publish it.
static void generate_backups(esp_mqtt_client_handle_t client) {
    for (int i = 0; i < max_guardians; i++) {
        ElectionKeyPair *sender = &pubkey_map[i];
        ElectionPartialKeyPairBackup backup;
        void *buffer;
        size_t len;
        generate_election_partial_key_backup(sender, &guardian, &backup);
        buffer = serialize_election_partial_key_backup(&backup, &len);
        esp_mqtt_client_enqueue(client, "backups", buffer, len, 2, 0, false);
        free(buffer);
        free_ElectionPartialKeyPairBackup(&backup);
    }
}

// Generate the guardian's key pair and publish the public key.
static void publish_public_key(esp_mqtt_client_handle_t client, const char *data, int data_len)
{
    void *buffer;
    size_t len;
    generate_election_key_pair(quorum, &guardian);
    buffer = serialize_election_key_pair(&guardian, &len);
    esp_mqtt_client_enqueue(client, "pub_keys", buffer, len, 2, 0,false);
    ESP_LOGI(TAG, "Sent Public Key");
    free(buffer);
}

// Deserialise the received public key and add it to the pubkey map. If all public keys have been received, generate backups.
static void handle_pubkeys(esp_mqtt_client_handle_t client, const char *data, int data_len)
{
    ElectionKeyPair sender;
    deserialize_election_key_pair((uint8_t*)data, data_len, &sender);
    ESP_LOGI(TAG, "pubkey_count: %d", pubkey_count);
    if(memcmp(sender.guardian_id, mac, 6) == 0)
    {
        ESP_LOGI(TAG, "Received own public key");
        free_ElectionKeyPair(&sender);
        return;
    }

    if(find_key_pair(sender.guardian_id) == NULL)
    {
        ESP_LOGI(TAG, "Adding Public Key");
        add_key_pair(&sender);
        if(pubkey_count == max_guardians)
        {   
            ESP_LOGI(TAG, "All Public Keys received");
            generate_backups(client);
            esp_mqtt_client_unsubscribe(client, "pub_keys");
        }
    } else {
        ESP_LOGI(TAG, "Public Key already exists");
        free_ElectionKeyPair(&sender);
    }
}

// Deserialise a received backup. If the backup is intended for this guardian, add it to the backup map. If all backups have been received, verify them.
static void handle_backups(esp_mqtt_client_handle_t client, const char *data, int data_len)
{
    ElectionPartialKeyPairBackup backup;
    deserialize_election_partial_key_backup((uint8_t*)data, data_len, &backup);

    if(memcmp(backup.receiver, mac, 6) != 0)
    {
        ESP_LOGI(TAG, "Backup not intended for this guardian");
        free_ElectionPartialKeyPairBackup(&backup);
        return;
    }

    if(find_backup(backup.sender) == NULL)
    {
        ESP_LOGI(TAG, "Adding Backup");
        add_backup(&backup);
        if(backup_count == max_guardians)
        {
            ESP_LOGI(TAG, "All Backups received");
            verify_backups(client);
            esp_mqtt_client_unsubscribe(client, "backups");
        }
    } else {
        ESP_LOGI(TAG, "Backup already exists");
        free_ElectionPartialKeyPairBackup(&backup);
    }
}

// Unimplemented
static void handle_challenge(esp_mqtt_client_handle_t client, const char *data, int data_len)
{
    ESP_LOGI(TAG, "Received challenge");
    ESP_LOGI(TAG, "unimplemented");
    return;
}

// Deserialise the ciphertext tally and compute the decryption share. Publish the decryption share.
static void handle_ciphertext_tally(esp_mqtt_client_handle_t client, const char *data, int data_len)
{
    CiphertextTally tally;
    DecryptionShare share;
    deserialize_ciphertext_tally((uint8_t*)data, data_len, &tally);
    //perform_measurement(&guardian, &tally);
    compute_decryption_share(&guardian, &tally, &share);
    free_CiphertextTally(&tally);
    void *buffer;
    size_t len;
    buffer = serialize_DecryptionShare(&share, &len);
    ESP_LOGI(TAG,"len: %d", len);
    esp_mqtt_client_enqueue(client, "decryption_share", buffer, len, 2, 0, false);
    free_DecryptionShare(&share);
}

// Function to add an entry to the pubkey map
static void add_key_pair(ElectionKeyPair *key_pair) {
    if (pubkey_count < max_guardians) {
        pubkey_map[pubkey_count++] = *key_pair;
    } else {
        printf("Key pair map is full\n");
    }
}

// Function to find an entry in the pubkey map
static ElectionKeyPair* find_key_pair(uint8_t *guardian_id) {
    for (int i = 0; i < max_guardians; i++) {
        if (memcmp(pubkey_map[i].guardian_id, guardian_id, 6) == 0) {
            return &pubkey_map[i];
        }
    }
    return NULL;
}

// Function to delete an entry from the pubkey map
static void delete_key_pair(uint8_t *guardian_id) {
    ElectionKeyPair *key_pair = find_key_pair(guardian_id);
    if (key_pair != NULL) {
        int index = key_pair - pubkey_map;
        free_ElectionKeyPair(&pubkey_map[index]);
        // Shift remaining elements to the left
        memmove(&pubkey_map[index], &pubkey_map[index + 1], (pubkey_count - index - 1) * sizeof(ElectionKeyPair));
        pubkey_count--;
    } else {
        printf("Guardian ID not found\n");
    }
}

// Function to add an entry to the backup map
static void add_backup(ElectionPartialKeyPairBackup *backup) {
    if (backup_count < max_guardians) {
        backup_map[backup_count++] = *backup;
    } else {
        printf("Key pair map is full\n");
    }
}

// Function to find an entry in the backup map
static ElectionPartialKeyPairBackup* find_backup(uint8_t *guardian_id) {
    for (int i = 0; i < max_guardians; i++) {
        if (memcmp(backup_map[i].sender, guardian_id, 6) == 0) {
            return &backup_map[i];
        }
    }
    return NULL;
}

// Function to delete an entry from the backup map
static void delete_backup(uint8_t *guardian_id) {
    ElectionPartialKeyPairBackup *backup = find_backup(guardian_id);
    if (backup != NULL) {
        int index = backup - backup_map;
        free_ElectionPartialKeyPairBackup(&backup_map[index]);
        // Shift remaining elements to the left
        memmove(&backup_map[index], &backup_map[index + 1], (backup_count - index - 1) * sizeof(ElectionPartialKeyPairBackup));
        backup_count--;
    } else {
        printf("Guardian ID not found\n");
    }
}

/**
 * @brief Start the MQTT client
 * 
 * This function initializes the MQTT client, registers the event handler and starts the client.
 */
void mqtt_app_start(void)
{
    esp_mqtt_client_config_t mqtt_cfg = {
        .broker.address.uri = "mqtt://192.168.12.1:1883",
    };
    esp_mqtt_client_handle_t client = esp_mqtt_client_init(&mqtt_cfg);
    esp_mqtt_client_register_event(client, ESP_EVENT_ANY_ID, mqtt_event_handler, NULL);
    esp_mqtt_client_start(client);

}
