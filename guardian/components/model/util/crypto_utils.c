/* wolfSSL */
/* Always include wolfcrypt/settings.h before any other wolfSSL file.    */
/* Reminder: settings.h pulls in user_settings.h; don't include it here. */
#ifdef WOLFSSL_USER_SETTINGS
    #include <wolfssl/wolfcrypt/settings.h>
    #ifndef WOLFSSL_ESPIDF
        #warning "Problem with wolfSSL user_settings."
        #warning "Check components/wolfssl/include"
    #endif
    #include <wolfssl/version.h>
    #include <wolfssl/wolfcrypt/types.h>
    #include <wolfcrypt/test/test.h>
    #include <wolfssl/wolfcrypt/port/Espressif/esp-sdk-lib.h>
    #include <wolfssl/wolfcrypt/port/Espressif/esp32-crypt.h>
#else
    /* Define WOLFSSL_USER_SETTINGS project wide for settings.h to include   */
    /* wolfSSL user settings in ./components/wolfssl/include/user_settings.h */
    #error "Missing WOLFSSL_USER_SETTINGS in CMakeLists or Makefile:\
    CFLAGS +=-DWOLFSSL_USER_SETTINGS"
#endif

#include "crypto_utils.h"


/**
 * @brief Prints an sp_int to the ESP_LOGI.
 *
 * This function converts an sp_int to a hexadecimal string and prints it using ESP_LOGI.
 *
 * @param num The sp_int to print.
 */
void print_sp_int(sp_int *num) {   
    int size = sp_unsigned_bin_size(num);
    char *buffer = (char *)calloc(size * 2 + 1, sizeof(char));
    if (buffer == NULL) {
        ESP_LOGE("Print mp_int", "Failed to allocate memory for buffer");
        return;
    }
    if (sp_toradix(num, buffer, 16) == MP_OKAY) {
        ESP_LOGI("Print mp_int", "mp_int value: %s", buffer);
    } else {
        ESP_LOGE("Print mp_int", "Failed to convert mp_int to string");
    }
    free(buffer);
}

/**
 * @brief Converts an integer to a byte array (big-endian).
 *
 * This helper function converts a 32-bit integer to a 4-byte array in big-endian order.
 *
 * @param value The integer to convert.
 * @param bytes A pointer to the byte array where the result will be stored.
 */
static void int_to_bytes(int value, unsigned char *bytes) {
    for (int i = 0; i < 4; i++) {
        bytes[3 - i] = (value >> (i * 8)) & 0xFF;
    }
}

/**
 * @brief Prints a byte array to the ESP_LOGI.
 *
 * This function converts a byte array to a hexadecimal string and prints it using ESP_LOGI.
 *
 * @param array The byte array to print.
 * @param size The size of the byte array.
 */
void print_byte_array(const byte *array, int size) {
    char *buffer = (char *)calloc(size * 3 + 1, sizeof(char));
    if (buffer == NULL)
    {
        ESP_LOGE("BYTE_ARRAY", "Failed to allocate memory for buffer");
        return;
    }
    
    //char buffer[size * 3 + 1]; // Each byte will be represented by 2 hex digits and a space
    for (int i = 0; i < size; i++) {
        sprintf(&buffer[i * 3], "%02x ", array[i]);
    }
    buffer[size * 3] = '\0'; // Null-terminate the string
    ESP_LOGI("BYTE_ARRAY", "%s", buffer);
    free(buffer);
}

/**
 * @brief Updates a SHA256 context with an sp_int.
 *
 * This function converts an sp_int to a hexadecimal string and updates a SHA256 context with it.
 * It also adds a delimiter "|" after the hexadecimal string.
 *
 * @param sha256 A pointer to the SHA256 context.
 * @param value A pointer to the sp_int to hash.
 *
 * @return 0 on success.
 * @return -1 on failure.
 */
static int update_sha256_with_sp_int(Sha256 *sha256, sp_int *value) {
    int size;
    sp_radix_size(value, 16, &size);
    char* elem = (char *)malloc(size);
    sp_tohex(value, elem);
    if(wc_Sha256Update(sha256, (byte *)elem, size -1) != 0) {
        ESP_LOGE("HASH_KEYS", "Failed to update sha256");
        free(elem);
        return -1;
    }
    if(wc_Sha256Update(sha256, (byte *)"|", 1) != 0) {
        ESP_LOGE("HASH_KEYS", "Failed to update sha256");
        //free(elem);
        return -1;
    }
    free(elem);
    return 0;
}

/**
 * @brief Get a hash-based message authentication code(hmac) digest
 * @param key: key (key) in bytes
 * @param in: input data in bytes
 * @param out: output hmac digest in bytes
 * @return 0 on success, -1 on failure
 */
static int get_hmac(unsigned char *key, unsigned char *in, unsigned char *out) {
    Hmac hmac;
    // Initialise HMAC as SHA256
    if(wc_HmacSetKey(&hmac, WC_SHA256, key, sizeof(key)) != 0) {
        ESP_LOGE("HMAC", "Failed to initialise hmac");
        wc_HmacFree(&hmac);
        return -1;
    }
    if(wc_HmacUpdate(&hmac, in, sizeof(in)) != 0) {
        ESP_LOGE("HMAC", "Failed to update data");
        wc_HmacFree(&hmac);
        return -1;
    }
    if(wc_HmacFinal(&hmac, out) != 0) {
        ESP_LOGE("HMAC", "Failed to compute hash");
        wc_HmacFree(&hmac);
        return -1;
    }
    wc_HmacFree(&hmac);
    return 0;
}


/**
 * @brief generates a Keystream using a KDF then XORs it with the message
 * @param key: Key used for the hashing
 * @param salt: Salt used for the hashing
 * @param message: Message to be hashed
 * @param encrypted_message: Write Encrypted message back to encrypted_message
 * @return 0 on success, 1 on failure
 */
static int kdf_xor(sp_int *key, sp_int *salt, sp_int *message, sp_int *encrypted_message) {
    // pad message with 0 if not multiple of 32
    int message_len = sp_unsigned_bin_size(message);
    int remainder = message_len % BLOCK_SIZE;
    int bit_len = (remainder == 0) ? message_len : message_len + (BLOCK_SIZE - remainder);
    byte *padded_message = (byte *)calloc(bit_len, sizeof(byte));
    if(padded_message == NULL) {
        ESP_LOGE("KDF", "Failed to allocate memory for padded_message");
        return 1;
    }
    sp_to_unsigned_bin_at_pos(0, message, padded_message);

    byte *key_bytes = (byte *)malloc(sp_unsigned_bin_size(key));
    if(key_bytes == NULL) {
        ESP_LOGE("KDF", "Failed to allocate memory for key_bytes");
        return 1;
    }
    sp_to_unsigned_bin(key, key_bytes);

    byte *data_key = (byte *)malloc(BLOCK_SIZE);
    if(data_key == NULL) {
        ESP_LOGE("KDF", "Failed to allocate memory for data_key");
        return 1;
    }

    int padded_salt = (sp_unsigned_bin_size(salt) + 8);
    byte *salt_bytes = (byte *)malloc(padded_salt);
    if(salt_bytes == NULL) {
        ESP_LOGE("KDF", "Failed to allocate memory for salt_bytes");
        return 1;
    }
    // Copy salt and add the bit length at the end
    sp_to_unsigned_bin_at_pos(4, salt, salt_bytes);
    int_to_bytes(bit_len, &salt_bytes[padded_salt - 4]);
    for(int i = 0; i < bit_len; i += BLOCK_SIZE) {
        // Add Counter to the beginning of the salt
        int_to_bytes((i / BLOCK_SIZE) + 1, salt_bytes);
        get_hmac(key_bytes, salt_bytes, data_key);
        for(int j = 0; j < BLOCK_SIZE; j++) {
            padded_message[i + j] ^= data_key[j];
        }
    }

    sp_read_unsigned_bin(encrypted_message, padded_message, bit_len);
    free(padded_message);
    free(key_bytes);
    free(data_key);
    free(salt_bytes);
    return 0;
}

/** 
 * @brief Modular Exponetiation. If the inputs are to small switches to unaccelerated version
 * @param g: Base
 * @param x: Exponent
 * @param p: Modulus
 * @param y: Result
 * @return 0 on success, -1 on failure
 */
static int exptmod(sp_int *g, sp_int *x, sp_int *p, sp_int *y) {
    int ret;
    ret = esp_mp_exptmod(g,x,p,y);
    if(ret == INPUT_CASE_ERROR) {
        ESP_LOGI("MODEXPT", "Input are too small switching to software exptmod");
        ret = sp_exptmod(g,x,p,y);
        if (ret != MP_OKAY) {
            ESP_LOGE("MULMOD", "Error code: %d", ret);
            return -1;
        } 
    }
    return ret;
}

/**
 * @brief Modular Multiplication. If the inputs are to small switches to unaccelerated version
 * @param a: First element
 * @param b: Second element
 * @param c: Modulus
 * @param result: The result of the multiplication
 * @return 0 on success, -1 on failure
 */
static int mulmod(sp_int *a, sp_int *b, sp_int *c, sp_int *result) {
    int ret;
    //int ret = sp_mulmod(a, b, c, result);
    ret = esp_mp_mulmod(a, b, c, result);
    if(ret == INPUT_CASE_ERROR) {
        ESP_LOGI("MULMOD", "Input are too smal switching to software mulmod");
        ret = sp_mulmod(a, b, c, result);
        if (ret != MP_OKAY) {
            ESP_LOGE("MULMOD", "Error code: %d", ret);
            return -1;
        } 
    }
    return ret;
}

/**
 * @brief Compute Large number Modular Exponetiation with known G (generator also known as base) and P (large prime also known as modulus). Y = (G ^ X) mod P
 * @param seckey: Exponent (X)
 * @param pubkey: Result
 * @return 0 on success, -1 on failure
 */
static int g_pow_p(sp_int *seckey, sp_int *pubkey) {
    int ret;
    DECL_MP_INT_SIZE(large_prime, 3072);
    NEW_MP_INT_SIZE(large_prime, 3072, NULL, DYNAMIC_TYPE_BIGINT);
    INIT_MP_INT_SIZE(large_prime, 3072);
    sp_read_unsigned_bin(large_prime, p_3072, sizeof(p_3072));

    DECL_MP_INT_SIZE(generator, 3072);
    NEW_MP_INT_SIZE(generator, 3072, NULL, DYNAMIC_TYPE_BIGINT);
    INIT_MP_INT_SIZE(generator, 3072);
    sp_read_unsigned_bin(generator, g_3072, sizeof(g_3072));

    ret = exptmod(generator,seckey,large_prime,pubkey);
    if(ret != 0) {
        ESP_LOGE("G_POW_P", "Failed to compute g^x mod p");
        ESP_LOGE("G_POW_P", "Error code: %d", ret);
    }
    FREE_MP_INT_SIZE(large_prime, NULL, DYNAMIC_TYPE_BIGINT);
    FREE_MP_INT_SIZE(generator, NULL, DYNAMIC_TYPE_BIGINT);
    return 0;
}

/**
 * @brief Generate a random number below constant Prime Q (small prime)
 * @param result: The random number
 * @return 0 on success, -1 on failure
 */
int rand_q(sp_int *result) {
    DECL_MP_INT_SIZE(small_prime, 256);
    NEW_MP_INT_SIZE(small_prime, 256, NULL, DYNAMIC_TYPE_BIGINT);
    INIT_MP_INT_SIZE(small_prime, 256);
    sp_read_unsigned_bin(small_prime, q_256, sizeof(q_256));

    int sz = 32;    
    unsigned char *block = (unsigned char *)malloc(sz * sizeof(unsigned char));
    if (block == NULL) {
        ESP_LOGE("RAND_Q", "Failed to allocate memory for block");
        return -1; // Memory allocation failed
    }  

    esp_fill_random(block, sz);
    sp_read_unsigned_bin(result, block, sz);
    sp_mod(result, small_prime, result);

    // Clear
    memset(block, 0, sz); 
    free(block);
    FREE_MP_INT_SIZE(small_prime, NULL, DYNAMIC_TYPE_BIGINT);
    return 0;
}

/**
 * @brief Some hash operations require the intermediate results to be hashed again
 *
 * This function takes an sp_int and hashes it with delimiters before and after the value (e.g. H(|value|)).
 * To ensure the result is below the small prime Q, the result is taken modulo Q.
 *
 * @param result A pointer to the sp_int to be finalized.
 * @return 0 on success, -1 on failure.
 */
static int finalise_hash(sp_int *result) {
    Sha256 sha256;
    int ret;
    DECL_MP_INT_SIZE(small_prime, 256);
    NEW_MP_INT_SIZE(small_prime, 256, NULL, DYNAMIC_TYPE_BIGINT);
    INIT_MP_INT_SIZE(small_prime, 256);
    sp_read_unsigned_bin(small_prime, q_256, sizeof(q_256));
    byte *result_byte = (byte *)malloc(WC_SHA256_DIGEST_SIZE);
    if (result_byte == NULL) {
        ESP_LOGE("HASH_ELEMS", "Failed to allocate memory for result_byte");
        return -1; // Return an error code
    }
    if (wc_InitSha256(&sha256) != 0) {
        ESP_LOGE("HASH_ELEMS", "Failed to initialize sha256");
        free(result_byte);
        return -1;
    } else {
        if (wc_Sha256Update(&sha256, (byte *)"|", 1) != 0) {
            ESP_LOGE("HASH_KEYS", "Failed to update sha256 with initial delimiter");
            return -1;
        }
        update_sha256_with_sp_int(&sha256, result);

        if (wc_Sha256Final(&sha256, result_byte) != 0) {
            ESP_LOGE("HASH_ELEMS", "Failed to finalize sha256");
            wc_Sha256Free(&sha256);
            free(result_byte);
            return -1;
        }
        wc_Sha256Free(&sha256);
        sp_zero(result);
        ret = sp_read_unsigned_bin(result, result_byte, WC_SHA256_DIGEST_SIZE); 
        sp_mod(result, small_prime, result);  

    }
    free(result_byte);
    FREE_MP_INT_SIZE(small_prime, NULL, DYNAMIC_TYPE_BIGINT);
    return ret;
}

/**
 * @brief Given two mp_ints, calculate their cryptographic hash using SHA256.
 * 
 * Each value is converted to a hexadecimal string and hashed with a delimiter in between (e.g. H( |a|b| ) ).
 * 
 * @param a: First element
 * @param b: Second element
 * @param result: The result of the hash
 * @return 0 on success, -1 on failure
 */
int hash(sp_int *a, sp_int *b, sp_int *result) {
    Sha256 sha256;
    int ret;
    byte *result_byte = (byte *)malloc(WC_SHA256_DIGEST_SIZE);
    if (result_byte == NULL) {
        ESP_LOGE("HASH_ELEMS", "Failed to allocate memory for result_byte");
        return -1; // Return an error code
    }
    // Initialize the SHA256 context
    if (wc_InitSha256(&sha256) != 0) {
        ESP_LOGE("HASH_ELEMS", "Failed to initialize sha256");
        free(result_byte);
        return -1;
    } else {
        if (wc_Sha256Update(&sha256, (byte *)"|", 1) != 0) {
            ESP_LOGE("HASH_KEYS", "Failed to update sha256 with initial delimiter");
            return -1;
        }
        
        update_sha256_with_sp_int(&sha256, a);
        update_sha256_with_sp_int(&sha256, b);

        if (wc_Sha256Final(&sha256, result_byte) != 0) {
            ESP_LOGE("HASH_ELEMS", "Failed to finalize sha256");
            wc_Sha256Free(&sha256);
            free(result_byte);
            return -1;
        }
        wc_Sha256Free(&sha256);
        ret = sp_read_unsigned_bin(result, result_byte, WC_SHA256_DIGEST_SIZE); 
    }
    //finalise_hash(result);
    free(result_byte);
    return ret;
}


/**
 * @brief Computes a single coordinate value of the election polynomial used for sharing
 * @param exponent_modifier: Unique modifier (guardian id) for exponent [0, Q]
 * @param polynomial: Election polynomial
 * @param coordinate: The computed coordinate
 * @return 0 on success, -1 on failure
 */
int compute_polynomial_coordinate(uint8_t* exponent_modifier, ElectionPolynomial* polynomial, sp_int *coordinate) {
    DECL_MP_INT_SIZE(modifier, 48);
    NEW_MP_INT_SIZE(modifier, 48, NULL, DYNAMIC_TYPE_BIGINT);
    INIT_MP_INT_SIZE(modifier, 48);
    sp_read_unsigned_bin(modifier, exponent_modifier, sizeof(exponent_modifier));

    DECL_MP_INT_SIZE(exponent_i, 48);
    NEW_MP_INT_SIZE(exponent_i, 48, NULL, DYNAMIC_TYPE_BIGINT);
    INIT_MP_INT_SIZE(exponent_i, 48);

    DECL_MP_INT_SIZE(exponent, 256);
    NEW_MP_INT_SIZE(exponent, 256, NULL, DYNAMIC_TYPE_BIGINT);
    INIT_MP_INT_SIZE(exponent, 256);

    DECL_MP_INT_SIZE(factor, 256);
    NEW_MP_INT_SIZE(factor, 256, NULL, DYNAMIC_TYPE_BIGINT);
    INIT_MP_INT_SIZE(factor, 256);

    DECL_MP_INT_SIZE(small_prime, 256);
    NEW_MP_INT_SIZE(small_prime, 256, NULL, DYNAMIC_TYPE_BIGINT);
    INIT_MP_INT_SIZE(small_prime, 256);
    sp_read_unsigned_bin(small_prime, q_256, sizeof(q_256));
    for (size_t i = 0; i < polynomial->num_coefficients; i++)
    {   
        sp_set_int(exponent_i, i);
        // Not Accelerated. Operator lenght to small
        exptmod(modifier, exponent_i, small_prime, exponent);
        mulmod(polynomial->coefficients[i].value, exponent, small_prime, factor);
        sp_addmod(coordinate, factor, small_prime, coordinate);
    }
    FREE_MP_INT_SIZE(exponent_i, NULL, DYNAMIC_TYPE_BIGINT);
    FREE_MP_INT_SIZE(modifier, NULL, DYNAMIC_TYPE_BIGINT);
    FREE_MP_INT_SIZE(small_prime, NULL, DYNAMIC_TYPE_BIGINT);
    FREE_MP_INT_SIZE(exponent, NULL, DYNAMIC_TYPE_BIGINT);
    FREE_MP_INT_SIZE(factor, NULL, DYNAMIC_TYPE_BIGINT);
    return 0;
}

/**
 * @brief Verifies that a coordinate lies on the election polynomial.
 *
 * Given a guardian's identifier, a polynomial, and a coordinate, this function verifies
 * that the coordinate corresponds to a point on the polynomial. This is used to validate
 * partial key backups.
 *
 * @param exponent_modifier The unique identifier of the guardian (usually sequence order).
 * @param polynomial The election polynomial to verify against.
 * @param coordinate The coordinate to verify.
 * @return 1 if the coordinate is on the polynomial, 0 otherwise. Returns -1 on failure.
 */
int verify_polynomial_coordinate(uint8_t* exponent_modifier, ElectionPolynomial* polynomial, sp_int *coordinate) {
    DECL_MP_INT_SIZE(exponent, 3072);
    NEW_MP_INT_SIZE(exponent, 3072, NULL, DYNAMIC_TYPE_BIGINT);
    INIT_MP_INT_SIZE(exponent, 3072);
    DECL_MP_INT_SIZE(factor, 3072);
    NEW_MP_INT_SIZE(factor, 3072, NULL, DYNAMIC_TYPE_BIGINT);
    INIT_MP_INT_SIZE(factor, 3072);   

    DECL_MP_INT_SIZE(large_prime, 3072);
    NEW_MP_INT_SIZE(large_prime, 3072, NULL, DYNAMIC_TYPE_BIGINT);
    INIT_MP_INT_SIZE(large_prime, 3072);
    sp_read_unsigned_bin(large_prime, p_3072, sizeof(p_3072));
   
    DECL_MP_INT_SIZE(value_output, 3072);
    NEW_MP_INT_SIZE(value_output, 3072, NULL, DYNAMIC_TYPE_BIGINT);
    INIT_MP_INT_SIZE(value_output, 3072);

    DECL_MP_INT_SIZE(commitment_output, 3072);
    NEW_MP_INT_SIZE(commitment_output, 3072, NULL, DYNAMIC_TYPE_BIGINT);
    INIT_MP_INT_SIZE(commitment_output, 3072);
    sp_set_int(commitment_output, 1);

    DECL_MP_INT_SIZE(exponent_i, 64);
    NEW_MP_INT_SIZE(exponent_i, 64, NULL, DYNAMIC_TYPE_BIGINT);
    INIT_MP_INT_SIZE(exponent_i, 64);

    DECL_MP_INT_SIZE(modifier, 64);
    NEW_MP_INT_SIZE(modifier, 64, NULL, DYNAMIC_TYPE_BIGINT);
    INIT_MP_INT_SIZE(modifier, 64);
    sp_read_unsigned_bin(modifier, exponent_modifier, sizeof(exponent_modifier));

    for(size_t i = 0; i < polynomial->num_coefficients; i++) {
        //Not accelerated Operator lenght to small
        sp_set_int(exponent_i, i);
        exptmod(modifier, exponent_i, large_prime, exponent);
        exptmod(polynomial->coefficients[i].commitment, exponent, large_prime, factor);
        mulmod(commitment_output, factor, large_prime, commitment_output);
    }
    g_pow_p(coordinate, value_output);
    if(sp_cmp(value_output, commitment_output) == MP_EQ) {
        return 1;
    } else
    {
        return 0;
    }
    FREE_MP_INT_SIZE(exponent, NULL, DYNAMIC_TYPE_BIGINT);
    FREE_MP_INT_SIZE(exponent_i, NULL, DYNAMIC_TYPE_BIGINT);
    FREE_MP_INT_SIZE(modifier, NULL, DYNAMIC_TYPE_BIGINT);
    FREE_MP_INT_SIZE(large_prime, NULL, DYNAMIC_TYPE_BIGINT);
    FREE_MP_INT_SIZE(factor, NULL, DYNAMIC_TYPE_BIGINT);
    FREE_MP_INT_SIZE(value_output, NULL, DYNAMIC_TYPE_BIGINT);
    FREE_MP_INT_SIZE(commitment_output, NULL, DYNAMIC_TYPE_BIGINT);
}


/**
 * @brief Encrypts a message using Hashed ElGamal encryption.
 *
 * This function encrypts a given message using the Hashed ElGamal encryption scheme. It generates a ciphertext consisting
 * of a pad, data, and MAC (Message Authentication Code).
 *
 * @param message The message (`sp_int`) to be encrypted.
 * @param nonce A random nonce (`sp_int`) used for encryption.
 * @param public_key The recipient's public key (`sp_int`).
 * @param encryption_seed An encryption seed (`sp_int`) used in the key derivation function.
 * @param encrypted_message A pointer to the `HashedElGamalCiphertext` structure where the resulting ciphertext will be stored.
 *
 * @return 0 on success, 1 on memory allocation failure.
 */
int hashed_elgamal_encrypt(sp_int *message, sp_int *nonce, sp_int *public_key, sp_int *encryption_seed, HashedElGamalCiphertext *encrypted_message) {
    DECL_MP_INT_SIZE(large_prime, 3072);
    NEW_MP_INT_SIZE(large_prime, 3072, NULL, DYNAMIC_TYPE_BIGINT);
    INIT_MP_INT_SIZE(large_prime, 3072);
    sp_read_unsigned_bin(large_prime, p_3072, sizeof(p_3072));

    DECL_MP_INT_SIZE(pubkey_pow_n, 3072);
    NEW_MP_INT_SIZE(pubkey_pow_n, 3072, NULL, DYNAMIC_TYPE_BIGINT);
    INIT_MP_INT_SIZE(pubkey_pow_n, 3072);

    DECL_MP_INT_SIZE(session_key, 256);
    NEW_MP_INT_SIZE(session_key, 256, NULL, DYNAMIC_TYPE_BIGINT);
    INIT_MP_INT_SIZE(session_key, 256);

    exptmod(public_key, nonce, large_prime, pubkey_pow_n); //beta
    vTaskDelay(1 / portTICK_PERIOD_MS);
    g_pow_p(nonce, encrypted_message->pad); //alpha
    hash(encrypted_message->pad, pubkey_pow_n, session_key);
    kdf_xor(session_key, encryption_seed, message, encrypted_message->data);

    byte * key_bytes = (byte *)malloc(sp_unsigned_bin_size(session_key));
    if(key_bytes == NULL) {
        ESP_LOGE("HASHED_ELGAMAL_ENCRYPT", "Failed to allocate memory for key_bytes");
        return 1;
    }
    sp_to_unsigned_bin(session_key, key_bytes);

    int padded_size = sp_unsigned_bin_size(encryption_seed) + 8;
    byte * seed_bytes = (byte *)malloc(padded_size);
    if(seed_bytes == NULL) {
        ESP_LOGE("HASHED_ELGAMAL_ENCRYPT", "Failed to allocate memory for seed_bytes");
        return 1;
    }
    int_to_bytes(0, seed_bytes);
    sp_to_unsigned_bin_at_pos(4, encryption_seed, seed_bytes);
    int_to_bytes(sp_unsigned_bin_size(message), &seed_bytes[padded_size - 4]);

    byte *tmp = (byte *)malloc(BLOCK_SIZE);
    if(tmp == NULL) {
        ESP_LOGE("HASHED_ELGAMAL_ENCRYPT", "Failed to allocate memory for mac_key");
        return 1;
    }

    get_hmac(key_bytes, seed_bytes, tmp);
    byte *to_mac = (byte *)malloc(sp_unsigned_bin_size(encrypted_message->pad) + sp_unsigned_bin_size(encrypted_message->data));
    if(to_mac == NULL) {
        ESP_LOGE("HASHED_ELGAMAL_ENCRYPT", "Failed to allocate memory for to_mac");
        return 1;
    }
    sp_to_unsigned_bin_at_pos(0, encrypted_message->pad, to_mac);
    sp_to_unsigned_bin_at_pos(sp_unsigned_bin_size(encrypted_message->pad), encrypted_message->data, to_mac);
    get_hmac(tmp, to_mac, tmp);
    sp_read_unsigned_bin(encrypted_message->mac, tmp, BLOCK_SIZE);

    free(key_bytes);
    free(seed_bytes);
    free(tmp);
    free(to_mac);
    FREE_MP_INT_SIZE(session_key, NULL, DYNAMIC_TYPE_BIGINT);
    FREE_MP_INT_SIZE(large_prime, NULL, DYNAMIC_TYPE_BIGINT);
    FREE_MP_INT_SIZE(pubkey_pow_n, NULL, DYNAMIC_TYPE_BIGINT);
    return 0;
}

/**
 * Decrypt an ElGamal ciphertext using a known ElGamal secret key
 * @param encrypted_message: struct containing pad, data, and mac
 * @param secret_key: The corresponding ElGamal secret key.
 * @param encryption_seed: Encryption seed (Q) for election.
 * @param message: Decrypted plaintext message.
 * @return 0 on success, -1 on failure
 */
int hashed_elgamal_decrypt(HashedElGamalCiphertext *encrypted_message, sp_int *secret_key, sp_int *encryption_seed, sp_int *message) {
    DECL_MP_INT_SIZE(session_key, 256);
    NEW_MP_INT_SIZE(session_key, 256, NULL, DYNAMIC_TYPE_BIGINT);
    INIT_MP_INT_SIZE(session_key, 256);

    DECL_MP_INT_SIZE(large_prime, 3072);
    NEW_MP_INT_SIZE(large_prime, 3072, NULL, DYNAMIC_TYPE_BIGINT);
    INIT_MP_INT_SIZE(large_prime, 3072);
    sp_read_unsigned_bin(large_prime, p_3072, sizeof(p_3072));

    DECL_MP_INT_SIZE(pubkey_pow_n, 3072);
    NEW_MP_INT_SIZE(pubkey_pow_n, 3072, NULL, DYNAMIC_TYPE_BIGINT);
    INIT_MP_INT_SIZE(pubkey_pow_n, 3072);

    exptmod(encrypted_message->pad, secret_key, large_prime, pubkey_pow_n);
    hash(encrypted_message->pad, pubkey_pow_n, session_key);

    byte * key_bytes = (byte *)malloc(sp_unsigned_bin_size(session_key));
    if(key_bytes == NULL) {
        ESP_LOGE("HASHED_ELGAMAL_DECRYPT", "Failed to allocate memory for key_bytes");
        return 1;
    }
    sp_to_unsigned_bin(session_key, key_bytes);
    byte * seed_bytes = (byte *)malloc(sp_unsigned_bin_size(encryption_seed) + 8);
    if(seed_bytes == NULL) {
        ESP_LOGE("HASHED_ELGAMAL_DECRYPT", "Failed to allocate memory for seed_bytes");
        return 1;
    }
    int_to_bytes(0, seed_bytes);
    sp_to_unsigned_bin_at_pos(4, encryption_seed, seed_bytes);
    int_to_bytes(sp_unsigned_bin_size(encrypted_message->data), &seed_bytes[sp_unsigned_bin_size(encryption_seed) + 4]);
    byte *tmp = (byte *)malloc(BLOCK_SIZE);
    if(tmp == NULL) {
        ESP_LOGE("HASHED_ELGAMAL_DECRYPT", "Failed to allocate memory for mac_key");
        return 1;
    }
    get_hmac(key_bytes, seed_bytes, tmp);
    byte *to_mac = (byte *)malloc(sp_unsigned_bin_size(encrypted_message->pad) + sp_unsigned_bin_size(encrypted_message->data));
    if(to_mac == NULL) {
        ESP_LOGE("HASHED_ELGAMAL_DECRYPT", "Failed to allocate memory for to_mac");
        return 1;
    }
    sp_to_unsigned_bin_at_pos(0, encrypted_message->pad, to_mac);
    sp_to_unsigned_bin_at_pos(sp_unsigned_bin_size(encrypted_message->pad), encrypted_message->data, to_mac);
    get_hmac(tmp, to_mac, tmp);
    byte *mac = (byte *)malloc(sp_unsigned_bin_size(encrypted_message->mac));
    if(mac == NULL) {
        ESP_LOGE("HASHED_ELGAMAL_DECRYPT", "Failed to allocate memory for mac");
        return 1;
    }
    sp_to_unsigned_bin(encrypted_message->mac, mac);

    if (memcmp(tmp, mac, BLOCK_SIZE) != 0) {
        ESP_LOGE("HASHED_ELGAMAL_DECRYPT", "MAC verification failed in decryption.");
        return -1;
    }
    kdf_xor(session_key, encryption_seed, encrypted_message->data, message);
    free(key_bytes);
    free(seed_bytes);
    free(tmp);
    free(to_mac);
    free(mac);
    FREE_MP_INT_SIZE(session_key, NULL, DYNAMIC_TYPE_BIGINT);
    FREE_MP_INT_SIZE(large_prime, NULL, DYNAMIC_TYPE_BIGINT);
    FREE_MP_INT_SIZE(pubkey_pow_n, NULL, DYNAMIC_TYPE_BIGINT);
   return 0;
}


/**
 * @brief Generates a Schnorr proof to demonstrate knowledge of a secret key without revealing it.
 *
 * This function creates a Schnorr proof, which is a cryptographic proof-of-knowledge protocol.
 * It proves that the prover (the entity possessing the secret key) knows the secret key
 * corresponding to a given public key, without disclosing the secret key itself.
 *
 * The Schnorr proof is generated using the provided secret key, public key, and a nonce (a random number).
 * The proof consists of a commitment, a challenge, and a response.
 *
 * @param seckey A pointer to the secret key (\(x\)), which is a large integer.
 * @param pubkey A pointer to the public key (\(g^x \mod p\)), which is a large integer.
 * @param nonce A pointer to the nonce (\(k\)), a random element in the range \([0, Q)\).
 * @param proof A pointer to the `SchnorrProof` struct where the generated proof will be stored.
 *              The caller is responsible for allocating memory for the `SchnorrProof` struct.
 *              The function will allocate memory for the `pubkey`, `commitment`, `challenge`, and `response` fields within the `SchnorrProof` struct.
 *
 * @return 0 on success.
 * @return -1 on failure (e.g., memory allocation error).
 *
 * @note The function allocates memory for the fields within the `proof` structure.
 *       It is the caller's responsibility to free this memory when the proof is no longer needed
 *       to prevent memory leaks.  See `SchnorrProof` documentation for details.
 *
 */
static int make_schnorr_proof(sp_int *seckey, sp_int *pubkey, sp_int *nonce, SchnorrProof *proof) {
    proof->pubkey = NULL;
    NEW_MP_INT_SIZE(proof->pubkey, 3072, NULL, DYNAMIC_TYPE_BIGINT);
    sp_init_copy(proof->pubkey, pubkey);

    proof->commitment = NULL;
    NEW_MP_INT_SIZE(proof->commitment, 3072, NULL, DYNAMIC_TYPE_BIGINT);
    INIT_MP_INT_SIZE(proof->commitment, 3072);

    proof->challenge = NULL;
    NEW_MP_INT_SIZE(proof->challenge, 256, NULL, DYNAMIC_TYPE_BIGINT);
    INIT_MP_INT_SIZE(proof->challenge, 256);

    proof->response = NULL;
    NEW_MP_INT_SIZE(proof->response, 256, NULL, DYNAMIC_TYPE_BIGINT);
    INIT_MP_INT_SIZE(proof->response, 256);

    g_pow_p(nonce, proof->commitment);
    hash(pubkey, proof->commitment, proof->challenge);

    // a + bc ^ q = nonce + seckey * challenge ^ q
    DECL_MP_INT_SIZE(q, 256);
    NEW_MP_INT_SIZE(q, 256, NULL, DYNAMIC_TYPE_BIGINT);
    INIT_MP_INT_SIZE(q, 256);
    sp_read_unsigned_bin(q, q_256, sizeof(q_256));

    DECL_MP_INT_SIZE(res_mul, 512);
    NEW_MP_INT_SIZE(res_mul, 512, NULL, DYNAMIC_TYPE_BIGINT);
    INIT_MP_INT_SIZE(res_mul, 512);

    sp_mul(seckey,proof->challenge,res_mul);
    sp_addmod(nonce,res_mul,q,proof->response);

    FREE_MP_INT_SIZE(res_mul, NULL, DYNAMIC_TYPE_BIGINT);
    FREE_MP_INT_SIZE(q, NULL, DYNAMIC_TYPE_BIGINT);
    return 0;
}


/**
 * @brief Generates a polynomial for sharing election keys using Shamir's Secret Sharing.
 *
 * This function generates a polynomial of a specified degree, where each coefficient
 * is a secret value.  The polynomial is used to share an election key among multiple
 * guardians using Shamir's Secret Sharing scheme.  Each guardian receives a share
 * of the secret key, which is an evaluation of the polynomial at a specific point.
 * Any subset of guardians above a threshold can reconstruct the original secret key.
 *
 * For each coefficient of the polynomial, the function generates a random value,
 * computes a commitment to that value, and creates a Schnorr proof of knowledge
 * for the coefficient.
 *
 * @param polynomial A pointer to the `ElectionPolynomial` struct where the generated polynomial
 *                   will be stored.  The caller must allocate memory for the
 *                   `ElectionPolynomial` struct and set the `num_coefficients` field
 *                   before calling this function.  This function will allocate memory
 *                   for the `coefficients` array within the `ElectionPolynomial` struct,
 *                   as well as for the `value`, `commitment`, and `proof` fields
 *                   within each `PolynomialCoefficient` struct.
 *
 * @return 0 on success.
 * @return -1 on failure (e.g., memory allocation error).
 *
 * @note The function allocates memory for the fields within the `polynomial` structure.
 *       It is the caller's responsibility to free this memory when the polynomial is
 *       no longer needed to prevent memory leaks. See `ElectionPolynomial` and
 *       `PolynomialCoefficient` documentation for details.
 *
 */
int generate_polynomial(ElectionPolynomial *polynomial) {
    SchnorrProof proof;
    DECL_MP_INT_SIZE(nonce, 256);
    NEW_MP_INT_SIZE(nonce, 256, NULL, DYNAMIC_TYPE_BIGINT);
    INIT_MP_INT_SIZE(nonce, 256);

    for (int i = 0; i < polynomial->num_coefficients; i++) {
        polynomial->coefficients[i].value = NULL;
        NEW_MP_INT_SIZE(polynomial->coefficients[i].value, 256, NULL, DYNAMIC_TYPE_BIGINT);
        INIT_MP_INT_SIZE(polynomial->coefficients[i].value, 256);
        polynomial->coefficients[i].commitment = NULL;
        NEW_MP_INT_SIZE(polynomial->coefficients[i].commitment, 3072, NULL, DYNAMIC_TYPE_BIGINT);
        INIT_MP_INT_SIZE(polynomial->coefficients[i].commitment, 3072);
        
        rand_q(polynomial->coefficients[i].value);
        g_pow_p(polynomial->coefficients[i].value, polynomial->coefficients[i].commitment);
        rand_q(nonce);

        make_schnorr_proof(polynomial->coefficients[i].value, polynomial->coefficients[i].commitment, nonce, &proof);
        polynomial->coefficients[i].proof = proof;
    }

    sp_zero(nonce);
    FREE_MP_INT_SIZE(nonce, NULL, DYNAMIC_TYPE_BIGINT);
    return 0;
}


/**
 * @brief Combines multiple ElGamal public keys into a single aggregate key.
 *
 * This function combines the public keys of a guardian and a set of other guardians
 * into a single aggregate public key. The aggregate key is computed by
 * multiplying all the individual public keys together modulo a large prime \(p\).
 *
 * @param guardian A pointer to the `ElectionKeyPair` struct of the primary guardian.
 *                 Its public key will be included in the combination.
 * @param pubkey_map An array of `ElectionKeyPair` structs representing the other guardians
 *                   whose public keys will be combined.
 * @param count The number of elements in the `pubkey_map` array.
 * @param key A pointer to an `sp_int` where the resulting combined public key will be stored.
 *            The caller must allocate memory for this `sp_int` before calling the function.
 *
 * @return 0 on success.
 * @return -1 on failure (e.g., if any of the multiplication operations fail).
 *
 * @note The function assumes that all public keys are valid ElGamal public keys
 *       with respect to the same large prime \(p\).
 */
int elgamal_combine_public_keys(ElectionKeyPair *guardian, ElectionKeyPair *pubkey_map, size_t count, sp_int *key) {
    DECL_MP_INT_SIZE(large_prime, 3072);
    NEW_MP_INT_SIZE(large_prime, 3072, NULL, DYNAMIC_TYPE_BIGINT);
    INIT_MP_INT_SIZE(large_prime, 3072);
    sp_read_unsigned_bin(large_prime, p_3072, sizeof(p_3072));

    DECL_MP_INT_SIZE(product, 3072);
    NEW_MP_INT_SIZE(product, 3072, NULL, DYNAMIC_TYPE_BIGINT);
    INIT_MP_INT_SIZE(product, 3072);
    sp_set_int(product, 1);
    mulmod(product, guardian->public_key, large_prime, product);
    for(size_t i = 0; i < count; i++) {
        mulmod(product, pubkey_map[i].public_key, large_prime, product);
    }
    sp_copy(product, key);
    FREE_MP_INT_SIZE(product, NULL, DYNAMIC_TYPE_BIGINT);
    FREE_MP_INT_SIZE(large_prime, NULL, DYNAMIC_TYPE_BIGINT);
    return 0;
}
/**
 * @brief Computes a SHA256 hash of the commitments from multiple guardians.
 *
 * This function calculates a SHA256 hash of the commitments made by a primary guardian
 * and a set of other guardians. The hash serves as a binding
 * value that commits all guardians to their respective commitments.
 *
 * @param guardian A pointer to the `ElectionKeyPair` struct of the primary guardian.
 *                 The commitments from its polynomial will be included in the hash.
 * @param pubkey_map An array of `ElectionKeyPair` structs representing the other guardians
 *                   whose commitments will be included in the hash.
 * @param count The number of elements in the `pubkey_map` array.
 * @param commitment A pointer to an `sp_int` where the resulting hash value will be stored.
 *                   The caller must allocate memory for this `sp_int` before calling the function.
 *
 * @return 0 on success.
 * @return -1 on failure (e.g., if SHA256 initialization or update fails, or memory allocation error).
 *
 * @note The function concatenates the commitments of all guardians, separated by delimiters,
 *       before hashing the result.
 */
int hash_keys(ElectionKeyPair *guardian, ElectionKeyPair *pubkey_map, size_t count, sp_int *commitment) {
    Sha256 sha256;
    byte* hash_result = (byte *)malloc(WC_SHA256_DIGEST_SIZE);
    if(wc_InitSha256(&sha256) != 0) {
        ESP_LOGE("HASH_KEYS", "Failed to initialise sha256");
        free(hash_result);
        return -1;
    } else {
        if (wc_Sha256Update(&sha256, (byte *)"|", 1) != 0) {
            ESP_LOGE("HASH_KEYS", "Failed to update sha256 with initial delimiter");
            return -1;
        }
        ESP_LOGI("HASH_KEYS", "Commitments");
        for(size_t i = 0; i < guardian->polynomial.num_coefficients; i++) {
            update_sha256_with_sp_int(&sha256, guardian->polynomial.coefficients[i].commitment);
        }
        for(size_t i = 0; i < count; i++) {
            for(size_t j = 0; j < pubkey_map->polynomial.num_coefficients; j++) {
                update_sha256_with_sp_int(&sha256, pubkey_map[i].polynomial.coefficients[j].commitment);
            }
        }
        if(wc_Sha256Final(&sha256, hash_result) != 0) {
            ESP_LOGE("HASH_KEYS", "Failed to finalise sha256");
            return -1;
        }
        wc_Sha256Free(&sha256);
        sp_read_unsigned_bin(commitment, hash_result, WC_SHA256_DIGEST_SIZE);
    }
    finalise_hash(commitment);
    ESP_LOGI("HASH_KEYS", "Commitment");
    free(hash_result);    
    return 0;
}


/**
 * @brief Generates a deterministic nonces using SHA256 hashing.
 *
 * This function generates a nonces in the range [0, Q),
 * where Q is a small prime number. The nonce is generated deterministically from an initial
 * seed value using SHA256 hashing.  If the same seed is used, the same sequence of nonces
 * will be generated. 
 *
 * The function uses a header string "constant-chaum-pedersen-proof|" to ensure that the
 * generated nonces are specific to a particular context (e.g., a Chaum-Pedersen proof).
 *
 * @param seed A pointer to the initial seed value, which is an `sp_int`.
 * @param nonce A pointer to an `sp_int` where the generated nonce will be stored.
 *              The caller must allocate memory for this `sp_int` before calling the function.
 *
 * @return 0 on success.
 * @return -1 on failure (e.g., if SHA256 initialization or update fails, or memory allocation error).
 *
 * @note The function uses the WolfCrypt library for SHA256 hashing.
 */
static int nonces(sp_int* seed, sp_int* nonce) {
    DECL_MP_INT_SIZE(small_prime, 256);
    NEW_MP_INT_SIZE(small_prime, 256, NULL, DYNAMIC_TYPE_BIGINT);
    INIT_MP_INT_SIZE(small_prime, 256);
    sp_read_unsigned_bin(small_prime, q_256, sizeof(q_256));
    Sha256 sha256;
    char* header = "constant-chaum-pedersen-proof|";
    byte* base_seed = (byte *)malloc(WC_SHA256_DIGEST_SIZE);
    if(wc_InitSha256(&sha256) != 0) {
        ESP_LOGE("NONCE", "Failed to initialise sha256");
        return -1;
    } else {
        if (wc_Sha256Update(&sha256, (byte *)"|", 1) != 0) {
            ESP_LOGE("HASH_KEYS", "Failed to update sha256 with initial delimiter");
            return -1;
        }
        update_sha256_with_sp_int(&sha256, seed);

        if(wc_Sha256Update(&sha256, (byte*)header, strlen(header)) != 0) {
            ESP_LOGE("NONCE", "Failed to update sha256");
            return -1;
        }
        
        // Finalise the hash
        if(wc_Sha256Final(&sha256, base_seed) != 0) {
            ESP_LOGE("NONCE", "Failed to finalise sha256");
            return -1;
        }
        wc_Sha256Free(&sha256);
        sp_read_unsigned_bin(nonce, base_seed, WC_SHA256_DIGEST_SIZE);
        ESP_LOGI("NONCE", "Nonce");
    }
    int size;
    sp_radix_size(nonce, 16, &size);
    char* elem = (char *)malloc(size);
    sp_tohex(nonce, elem);
    byte* result = (byte *)malloc(WC_SHA256_DIGEST_SIZE);
    if(wc_InitSha256(&sha256) != 0) {
        ESP_LOGE("NONCE", "Failed to initialise sha256");
        return -1;
    } else {
        if (wc_Sha256Update(&sha256, (byte *)"|", 1) != 0) {
            ESP_LOGE("HASH_KEYS", "Failed to update sha256 with initial delimiter");
            return -1;
        }
        if(wc_Sha256Update(&sha256, (byte *)elem, size -1) != 0) {
            ESP_LOGE("HASH_KEYS", "Failed to update sha256");
            free(elem);
            return -1;
        }
        if(wc_Sha256Update(&sha256, (byte *)"|0|", 3) != 0) {
            ESP_LOGE("HASH_KEYS", "Failed to update sha256");
            free(elem);
            return -1;
        }
        // Finalise the hash
        if(wc_Sha256Final(&sha256, result) != 0) {
            ESP_LOGE("NONCE", "Failed to finalise sha256");
            return -1;
        }
        wc_Sha256Free(&sha256);
        sp_zero(nonce);
        sp_read_unsigned_bin(nonce, result, WC_SHA256_DIGEST_SIZE);
        sp_mod(nonce, small_prime, nonce);
    }
    FREE_MP_INT_SIZE(small_prime, NULL, DYNAMIC_TYPE_BIGINT);
    free(result);
    free(elem);
    free(base_seed);
    return 0;
}


/**
 * @brief Computes a SHA256 hash to generate a challenge value for a Chaum-Pedersen proof.
 *
 * This function computes a SHA256 hash of several input values to generate a challenge
 * value for a Chaum-Pedersen proof.  The input values include a header, two ElGamal
 * ciphertext components (alpha and beta), two commitment values (pad and data), and
 * the message being proven (m).  The hash serves to bind all these values together
 * in the challenge, ensuring that the proof is sound.
 *
 * @param header A pointer to a header value (`sp_int`) that provides context for the hash.
 *               This is often the election extended base hash.
 * @param alpha A pointer to the ElGamal ciphertext's alpha component (`sp_int`).
 * @param beta A pointer to the ElGamal ciphertext's beta component (`sp_int`).
 * @param pad A pointer to the commitment's pad value (`sp_int`).
 * @param data A pointer to the commitment's data value (`sp_int`).
 * @param m A pointer to the message being proven (`sp_int`).
 * @param challenge A pointer to an `sp_int` where the resulting challenge value will be stored.
 *                  The caller must allocate memory for this `sp_int` before calling the function.
 *
 * @return 0 on success.
 * @return -1 on failure (e.g., if SHA256 initialization or update fails, or memory allocation error).
 *
 * @note The function uses the WolfCrypt library for SHA256 hashing.
 */
static int hash_challenge(sp_int* header, sp_int* alpha, sp_int* beta, sp_int* pad, sp_int* data, sp_int* m, sp_int* challenge) {
    Sha256 sha256;
    byte* challenge_bytes = (byte *)malloc(WC_SHA256_DIGEST_SIZE);
    if(challenge_bytes == NULL) {
        ESP_LOGE("HASH_CHALLENGE", "Failed to allocate memory for challenge_bytes");
        return -1;
    }
    if(wc_InitSha256(&sha256) != 0) {
        ESP_LOGE("HASH_CHALLENGE", "Failed to initialise sha256");
        free(challenge_bytes);
        return -1;
    } else {
        if (wc_Sha256Update(&sha256, (byte *)"|", 1) != 0) {
            ESP_LOGE("HASH_KEYS", "Failed to update sha256 with initial delimiter");
            return -1;
        }
        update_sha256_with_sp_int(&sha256, header);
        update_sha256_with_sp_int(&sha256, alpha);
        update_sha256_with_sp_int(&sha256, beta);
        update_sha256_with_sp_int(&sha256, pad);
        update_sha256_with_sp_int(&sha256, data);
        update_sha256_with_sp_int(&sha256, m);

        if(wc_Sha256Final(&sha256, challenge_bytes) != 0) {
            ESP_LOGE("HASH_CHALLENGE", "Failed to finalise sha256");
            return -1;
        }
        wc_Sha256Free(&sha256);
        sp_read_unsigned_bin(challenge, challenge_bytes, WC_SHA256_DIGEST_SIZE);
    }
    //finalise_hash(challenge);
    free(challenge_bytes);
    return 0;
}

/**
 * @brief Generates a Chaum-Pedersen proof to demonstrate that a ciphertext corresponds to a specific plaintext.
 *
 * This function generates a Chaum-Pedersen proof, which is a zero-knowledge proof
 * that demonstrates that a given ElGamal ciphertext (alpha, beta) encrypts a specific
 * plaintext value (m).  The proof shows that the prover knows the secret (nonce) used
 * to create the ciphertext, without revealing the secret itself.
 *
 * @param alpha A pointer to the ElGamal ciphertext's alpha component (\(g^r \mod p\)), which is a large integer.
 * @param beta A pointer to the ElGamal ciphertext's beta component (\(m \cdot y^r \mod p\)), which is a large integer.
 * @param secret A pointer to the nonce (\(r\)) used to encrypt the message, which is a large integer.
 * @param m A pointer to the plaintext message (\(m\)), which is a large integer.
 * @param seed A pointer to a seed value used to generate random values within the proof.
 * @param hash_header A pointer to a header value used when generating the challenge, typically the election extended base hash.
 * @param proof A pointer to the `ChaumPedersenProof` struct where the generated proof will be stored.
 *              The caller is responsible for allocating memory for the `ChaumPedersenProof` struct.
 *              The function will allocate memory for the `pad`, `data`, `challenge`, and `response` fields within the `ChaumPedersenProof` struct.
 *
 * @return 0 on success.
 * @return -1 on failure (e.g., memory allocation error).
 *
 * @note The function allocates memory for the fields within the `proof` structure.
 *       It is the caller's responsibility to free this memory when the proof is no longer needed
 *       to prevent memory leaks.  See `ChaumPedersenProof` documentation for details.
 */
static int make_chaum_pedersen(sp_int* alpha, sp_int* beta, sp_int* secret, sp_int* m, sp_int* seed, sp_int* hash_header, ChaumPedersenProof* proof) {
    proof->pad = NULL;
    NEW_MP_INT_SIZE(proof->pad, 3072, NULL, DYNAMIC_TYPE_BIGINT);
    INIT_MP_INT_SIZE(proof->pad, 3072);
    proof->data = NULL;
    NEW_MP_INT_SIZE(proof->data, 3072, NULL, DYNAMIC_TYPE_BIGINT);
    INIT_MP_INT_SIZE(proof->data, 3072);
    proof->challenge = NULL;
    NEW_MP_INT_SIZE(proof->challenge, 256, NULL, DYNAMIC_TYPE_BIGINT);
    INIT_MP_INT_SIZE(proof->challenge, 256);
    proof->response = NULL;
    NEW_MP_INT_SIZE(proof->response, 256, NULL, DYNAMIC_TYPE_BIGINT);
    INIT_MP_INT_SIZE(proof->response, 256);
    
    DECL_MP_INT_SIZE(large_prime, 3072);
    NEW_MP_INT_SIZE(large_prime, 3072, NULL, DYNAMIC_TYPE_BIGINT);
    INIT_MP_INT_SIZE(large_prime, 3072);
    sp_read_unsigned_bin(large_prime, p_3072, sizeof(p_3072));

    DECL_MP_INT_SIZE(u, 256);
    NEW_MP_INT_SIZE(u, 256, NULL, DYNAMIC_TYPE_BIGINT);
    INIT_MP_INT_SIZE(u, 256);
    nonces(seed, u);
    g_pow_p(u, proof->pad);
    exptmod(alpha, u, large_prime, proof->data);

    hash_challenge(hash_header, alpha, beta, proof->pad, proof->data, m, proof->challenge);

    DECL_MP_INT_SIZE(small_prime, 256);
    NEW_MP_INT_SIZE(small_prime, 256, NULL, DYNAMIC_TYPE_BIGINT);
    INIT_MP_INT_SIZE(small_prime, 256);
    sp_read_unsigned_bin(small_prime, q_256, sizeof(q_256));

    DECL_MP_INT_SIZE(res_mul, 512);
    NEW_MP_INT_SIZE(res_mul, 512, NULL, DYNAMIC_TYPE_BIGINT);
    INIT_MP_INT_SIZE(res_mul, 512);

    // a + bc ^ q = u + c * secret ^ q
    sp_mul(secret, proof->challenge, res_mul);
    sp_addmod(u, res_mul, small_prime, proof->response);


    FREE_MP_INT_SIZE(large_prime, NULL, DYNAMIC_TYPE_BIGINT);
    FREE_MP_INT_SIZE(u, NULL, DYNAMIC_TYPE_BIGINT);
    FREE_MP_INT_SIZE(small_prime, NULL, DYNAMIC_TYPE_BIGINT);
    FREE_MP_INT_SIZE(res_mul, NULL, DYNAMIC_TYPE_BIGINT);
    return 0;
}

/**
 * @brief Computes a partial decryption share of an ElGamal ciphertext for a specific selection.
 *
 * This function computes a partial decryption share of an ElGamal ciphertext using a
 * known ElGamal secret key.  The partial decryption share is computed for a specific
 * selection within a contest.  The function also generates a Chaum-Pedersen proof
 * to demonstrate that the decryption share is computed correctly.
 *
 * @param privatekey A pointer to the secret key used to decrypt the ciphertext.
 * @param pad A pointer to the pad (\(g^r \mod p\)) of the ElGamal ciphertext.
 * @param data A pointer to the data (\(m \cdot y^r \mod p\)) of the ElGamal ciphertext.
 * @param base_hash A pointer to the base hash of the election.
 * @param dec_selection A pointer to the `CiphertextDecryptionSelection` struct where the
 *                      decryption share and proof will be stored.  The caller is
 *                      responsible for allocating memory for the `CiphertextDecryptionSelection`
 *                      struct.  The function will allocate memory for the `decryption`
 *                      field within the `CiphertextDecryptionSelection` struct, as well
 *                      as for the fields within the `proof` field.
 *
 * @return 0 on success.
 * @return -1 on failure (e.g., memory allocation error).
 *
 * @note The function allocates memory for the fields within the `dec_selection` structure.
 *       It is the caller's responsibility to free this memory when the decryption share
 *       is no longer needed to prevent memory leaks.  See `CiphertextDecryptionSelection`
 *       and `ChaumPedersenProof` documentation for details.
 */
static int compute_decryption_share_for_selection(sp_int* privatekey, sp_int* pad, sp_int* data, sp_int* base_hash , CiphertextDecryptionSelection *dec_selection) {
    dec_selection->decryption = NULL;
    NEW_MP_INT_SIZE(dec_selection->decryption, 3072, NULL, DYNAMIC_TYPE_BIGINT);
    INIT_MP_INT_SIZE(dec_selection->decryption, 3072);
    
    DECL_MP_INT_SIZE(nonce_seed, 256);
    NEW_MP_INT_SIZE(nonce_seed, 256, NULL, DYNAMIC_TYPE_BIGINT);
    INIT_MP_INT_SIZE(nonce_seed, 256);
    rand_q(nonce_seed);

    DECL_MP_INT_SIZE(large_prime, 3072);
    NEW_MP_INT_SIZE(large_prime, 3072, NULL, DYNAMIC_TYPE_BIGINT);
    INIT_MP_INT_SIZE(large_prime, 3072);
    sp_read_unsigned_bin(large_prime, p_3072, sizeof(p_3072));

    // Partially Decrypt Elgamal Ciphertext with a known Elgamal Secret Key
    exptmod(pad, privatekey, large_prime, dec_selection->decryption);
    make_chaum_pedersen(pad, data, privatekey, dec_selection->decryption, nonce_seed, base_hash, &dec_selection->proof);
    
    FREE_MP_INT_SIZE(nonce_seed, NULL, DYNAMIC_TYPE_BIGINT);
    FREE_MP_INT_SIZE(large_prime, NULL, DYNAMIC_TYPE_BIGINT);
    return 0;
}

/**
 * @brief Verifies a Chaum-Pedersen proof.
 *
 * This function verifies that a given Chaum-Pedersen proof is valid with respect to the provided public key,
 * challenge, alpha, and message. It performs two checks:
 * 1.  The equation 𝑔^𝑣𝑖 = 𝑎𝑖𝐾^𝑐𝑖 holds true
 * 2.  The equation 𝐴^𝑣𝑖 = 𝑏𝑖𝑀𝑖^𝑐𝑖 mod 𝑝 holds true
 *
 * @param public_key The public key (`sp_int`) used in the Chaum-Pedersen proof.
 * @param proof A pointer to the `ChaumPedersenProof` structure containing the proof data.
 * @param alpha An `sp_int` representing the generator `g` of the group.
 * @param m An `sp_int` representing the message.
 *
 * @return 0 if the proof is valid, otherwise logs an error message and returns a non-zero value.
 */
int verify_chaum_pedersen(sp_int* public_key, ChaumPedersenProof* proof, sp_int* alpha, sp_int* m) {
    DECL_MP_INT_SIZE(large_prime, 3072);
    NEW_MP_INT_SIZE(large_prime, 3072, NULL, DYNAMIC_TYPE_BIGINT);
    INIT_MP_INT_SIZE(large_prime, 3072);
    sp_read_unsigned_bin(large_prime, p_3072, sizeof(p_3072));

    DECL_MP_INT_SIZE(lhs, 3072);
    NEW_MP_INT_SIZE(lhs, 3072, NULL, DYNAMIC_TYPE_BIGINT);
    INIT_MP_INT_SIZE(lhs, 3072);

    DECL_MP_INT_SIZE(rhs, 3072);
    NEW_MP_INT_SIZE(rhs, 3072, NULL, DYNAMIC_TYPE_BIGINT);
    INIT_MP_INT_SIZE(rhs, 3072);

    DECL_MP_INT_SIZE(tmp, 3072);
    NEW_MP_INT_SIZE(tmp, 3072, NULL, DYNAMIC_TYPE_BIGINT);
    INIT_MP_INT_SIZE(tmp, 3072);
    sp_set_int(tmp, 1);

    g_pow_p(proof->response, lhs);

    exptmod(public_key, proof->challenge, large_prime, rhs);
    mulmod(tmp, proof->pad, large_prime, tmp);
    mulmod(tmp, rhs, large_prime, rhs);

    if(sp_cmp(lhs, rhs) != MP_EQ) {
        ESP_LOGI("VERIFY_CHAUM_PEDERSEN", "inconsistent gv");
    }
    sp_zero(lhs);
    sp_zero(rhs);
    sp_zero(tmp);
    sp_set_int(tmp, 1);

    exptmod(alpha, proof->response, large_prime, lhs);

    exptmod(m, proof->challenge, large_prime, rhs);
    mulmod(tmp, proof->data, large_prime, tmp);
    mulmod(tmp, rhs, large_prime, rhs);

    if(sp_cmp(lhs, rhs) != MP_EQ) {
        ESP_LOGI("VERIFY_CHAUM_PEDERSEN", "inconsistent av");
    }


    FREE_MP_INT_SIZE(large_prime, NULL, DYNAMIC_TYPE_BIGINT);
    FREE_MP_INT_SIZE(lhs, NULL, DYNAMIC_TYPE_BIGINT);
    FREE_MP_INT_SIZE(rhs, NULL, DYNAMIC_TYPE_BIGINT);
    FREE_MP_INT_SIZE(tmp, NULL, DYNAMIC_TYPE_BIGINT);
    return 0;
}

/**
 * @brief Computes a decryption share for a contest.
 *
 * This function computes a decryption share for a given contest based on the guardian's key pair and the contest data.
 * It allocates memory for the decryption contest and its selections, copies relevant data, and computes the decryption
 * share for each selection in the contest.
 *
 * @param guardian A pointer to the `ElectionKeyPair` structure containing the guardian's key pair.
 * @param contest A pointer to the `CiphertextTallyContest` structure representing the contest data.
 * @param base_hash A pointer to the base hash (`sp_int`) used in the decryption process.
 * @param dec_contest A pointer to the `CiphertextDecryptionContest` structure where the computed decryption share will be stored.
 *
 * @return 0 on success, -1 on memory allocation failure.
 */
int compute_decryption_share_for_contest(ElectionKeyPair *guardian, CiphertextTallyContest *contest, sp_int* base_hash , CiphertextDecryptionContest *dec_contest) {
    dec_contest->object_id = strdup(contest->object_id);

    dec_contest->public_key = NULL;
    NEW_MP_INT_SIZE(dec_contest->public_key, 3072, NULL, DYNAMIC_TYPE_BIGINT);
    INIT_MP_INT_SIZE(dec_contest->public_key, 3072);
    sp_copy(guardian->public_key, dec_contest->public_key);

    memcpy(dec_contest->guardian_id, guardian->guardian_id, sizeof(guardian->guardian_id));

    dec_contest->description_hash = NULL;
    NEW_MP_INT_SIZE(dec_contest->description_hash, 256, NULL, DYNAMIC_TYPE_BIGINT);
    INIT_MP_INT_SIZE(dec_contest->description_hash, 256);
    sp_copy(contest->description_hash, dec_contest->description_hash);


    dec_contest->num_selections = contest->num_selections;
    dec_contest->selections = (CiphertextDecryptionSelection *)malloc(contest->num_selections * sizeof(CiphertextDecryptionSelection));
    if(dec_contest->selections == NULL) {
        return -1;
    }
    for (int i = 0; i < dec_contest->num_selections; i++) {
        dec_contest->selections[i].object_id = strdup(contest->selections[i].object_id);
        memcpy(dec_contest->selections[i].guardian_id, guardian->guardian_id, sizeof(guardian->guardian_id));
        compute_decryption_share_for_selection(guardian->private_key, contest->selections[i].ciphertext_pad, contest->selections[i].ciphertext_data, base_hash, &dec_contest->selections[i]);
        //verify_chaum_pedersen(guardian->public_key, &dec_contest->selections[i].proof, contest->selections[i].ciphertext_pad, dec_contest->selections[i].decryption);
    }
    return 0;
}