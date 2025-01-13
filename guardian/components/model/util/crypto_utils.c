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

void int_to_bytes(int value, unsigned char *bytes) {
    for (int i = 0; i < 4; i++) {
        bytes[3 - i] = (value >> (i * 8)) & 0xFF;
    }
}

// Function to print byte array
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
 * @brief generates a Keystream using a KDF then XORs it with the message
 * @param key: Key used for the hashing
 * @param salt: Salt used for the hashing
 * @param message: Message to be hashed
 * @param encrypted_message: Write Encrypted message back to encrypted_message
 * @return 0 on success, 1 on failure
 */
int kdf_xor(sp_int *key, sp_int *salt, sp_int *message, sp_int *encrypted_message) {
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
 * @brief Compute Large number Modular Exponetiation with hardware Y = (G ^ X) mod P. If the inputs are to small switches to unaccelerated version
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
 * @brief Compute Large number Modular Exponetiation with known G (generator also known as base) and P (large prime also known as modulus). Y = (G ^ X) mod P
 * @param seckey: Exponent
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

    ret = esp_mp_exptmod(generator,seckey,large_prime,pubkey);
    if(ret != 0) {
        ESP_LOGE("G_POW_P", "Failed to compute g^x mod p");
        ESP_LOGE("G_POW_P", "Error code: %d", ret);
    }
    FREE_MP_INT_SIZE(large_prime, NULL, DYNAMIC_TYPE_BIGINT);
    FREE_MP_INT_SIZE(generator, NULL, DYNAMIC_TYPE_BIGINT);
    return 0;
}

/**
 * @brief Generate a random number below Q
 * Q is very close to the maximum value for a 256 bit number. It might be worth to compare and regenerate in case mod is expensive
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
 * @brief Given two mp_ints, calculate their cryptographic hash using SHA256.
 * Possible collision. In the python implementation a delimiter (|) is used
 * @param a: First element
 * @param b: Second element
 * @param result: The result of the hash
 * @return 0 on success, -1 on failure
 */
int hash(sp_int *a, sp_int *b, sp_int *result) {
    int ret;
    word32 a_size = sp_unsigned_bin_size(a);
    word32 b_size = sp_unsigned_bin_size(b); 
    word32 tmp_size = a_size + b_size;
    
    byte *tmp = (byte *)malloc(tmp_size);
    if (tmp == NULL) {
        ESP_LOGE("HASH_ELEMS", "Failed to allocate memory for tmp");
        return -1; // Return an error code
    }
    // Concatenate the two mp_ints
    ret = sp_to_unsigned_bin_at_pos(0, a, tmp);
    ret = sp_to_unsigned_bin_at_pos(a_size,b, tmp);

    byte *result_byte = (byte *)malloc(WC_SHA256_DIGEST_SIZE);
    if (result_byte == NULL) {
        ESP_LOGE("HASH_ELEMS", "Failed to allocate memory for result_byte");
        return -1; // Return an error code
    }

    // Conveniencefunction. Handles Initialisation, Update and Finalisation
    if ((ret = wc_Sha256Hash(tmp, tmp_size, result_byte)) != 0) {
        WOLFSSL_MSG("Hashing Failed");
        return ret;
    }

    ret = sp_read_unsigned_bin(result, result_byte, WC_SHA256_DIGEST_SIZE);   
    free(tmp);
    free(result_byte);
    return ret;
}


/**
 * @brief Computes a single coordinate value of the election polynomial used for sharing
 * @param exponent_modifier: Unique modifier (usually sequence order) for exponent [0, Q]
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
        sp_mulmod(polynomial->coefficients[i].value, exponent, small_prime, factor);
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
 * @brief Computes a single coordinate value of the election polynomial used for sharing
 * @param exponent_modifier: Unique modifier (usually sequence order) for exponent [0, Q]
 * @param polynomial: Election polynomial
 * @param coordinate: The computed coordinate
 * @return 0 on success, -1 on failure
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
        sp_mulmod(commitment_output, factor, large_prime, commitment_output);
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
 * @brief Get a hash-based message authentication code(hmac) digest
 * @param key: key (key) in bytes
 * @return error_code
 */
int get_hmac(unsigned char *key, unsigned char *in, unsigned char *out) {
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
 * Encrypts a variable length message with a given random nonce and an ElGamal public key.
 * @param message: message (m) to encrypt; must be in bytes.
 * @param nonce: Randomly chosen nonce in [1, Q).
 * @param public_key: ElGamal public key.
 * @param encryption_seed: Encryption seed (Q) for election.
 * @param encrypted_coordinate: The encrypted message.
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

    esp_mp_exptmod(public_key, nonce, large_prime, pubkey_pow_n); //beta
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
 * @param secret_key: The corresponding ElGamal secret key.
 * @param encryption_seed: Encryption seed (Q) for election.
 * @param plaintext: Decrypted plaintext message.
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

    esp_mp_exptmod(encrypted_message->pad, secret_key, large_prime, pubkey_pow_n);
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
 * @brief Given an ElGamal keypair and a nonce, generates a proof that the prover knows the secret key without revealing it.
 * @param seckey: The secret key
 * @param pubkey: The public key
 * @param nonce: A random element in [0,Q)
 * @param proof: The Schnorr proof
 * @return 0 on success, -1 on failure
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
    NEW_MP_INT_SIZE(proof->response, 4096, NULL, DYNAMIC_TYPE_BIGINT);
    INIT_MP_INT_SIZE(proof->response, 4096);

    g_pow_p(nonce, proof->commitment);
    hash(pubkey, proof->commitment, proof->challenge);

    // a + bc ^ q = nonce + seckey * challenge ^ q
    DECL_MP_INT_SIZE(q, 256);
    NEW_MP_INT_SIZE(q, 256, NULL, DYNAMIC_TYPE_BIGINT);
    INIT_MP_INT_SIZE(q, 256);
    sp_read_unsigned_bin(q, q_256, sizeof(q_256));

    sp_mul(seckey,proof->challenge,proof->response);
    sp_addmod(nonce,proof->response,q,proof->response);

    FREE_MP_INT_SIZE(q, NULL, DYNAMIC_TYPE_BIGINT);
    return 0;
}


/**
 * @brief Generates a polynomial for sharing election keys
 * @param coefficients:  Number of coefficients of polynomial
 * @param Polynomial used to share election keys. Contains value, commitment, and proof
 * @return 0 on success, -1 on failure
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
 * @brief Modular Multiplication. If the input parameters are to small switches to the software method
 * @param a: First element
 * @param b: Second element
 * @param c: Modulus
 * @param result: The result of the multiplication
 */
static int mulmod(sp_int *a, sp_int *b, sp_int *c, sp_int *result) {
    int ret;
    ret = esp_mp_mulmod(a, b, c, result);
    if(ret == INPUT_CASE_ERROR) {
        ESP_LOGI("MULMOD", "Input are too smal switching to software mulmod");
        ret = mp_mulmod(a, b, c, result);
        if (ret != MP_OKAY) {
            ESP_LOGE("MULMOD", "Error code: %d", ret);
            return -1;
        } 
    }
    return ret;
}

int elgamal_combine_public_keys(ElectionKeyPair *pubkey_map, size_t count, ElectionJointKey *joint_key) {
    DECL_MP_INT_SIZE(large_prime, 3072);
    NEW_MP_INT_SIZE(large_prime, 3072, NULL, DYNAMIC_TYPE_BIGINT);
    INIT_MP_INT_SIZE(large_prime, 3072);
    sp_read_unsigned_bin(large_prime, p_3072, sizeof(p_3072));

    DECL_MP_INT_SIZE(product, 3072);
    NEW_MP_INT_SIZE(product, 3072, NULL, DYNAMIC_TYPE_BIGINT);
    INIT_MP_INT_SIZE(product, 3072);
    sp_set_int(product, 1);
    //sp_set_int(joint_key->joint_key, 1);

    for(size_t i = 0; i < count; i++) {
        //print_sp_int(joint_key->joint_key);
        print_sp_int(pubkey_map[i].public_key);
        //imputs to small
        mulmod(product, pubkey_map[i].public_key, large_prime, product);
    }
    sp_copy(product, joint_key->joint_key);
    FREE_MP_INT_SIZE(large_prime, NULL, DYNAMIC_TYPE_BIGINT);
    return 0;
}

int hash_keys(ElectionKeyPair *pubkey_map, size_t count, ElectionJointKey *joint_key) {
    Sha256 sha256[1];
    byte* commitment = (byte *)malloc(WC_SHA256_DIGEST_SIZE);
    if(wc_InitSha256(sha256) != 0) {
        ESP_LOGE("HASH_KEYS", "Failed to initialise sha256");
        return -1;
    } else {
        for(size_t i = 0; i < count; i++) {
            int size = sp_unsigned_bin_size(pubkey_map[i].public_key);
            byte* elem = (byte *)malloc(size);
            sp_to_unsigned_bin(pubkey_map[i].public_key, elem);
            if(wc_Sha256Update(sha256, elem, size) != 0) {
                ESP_LOGE("HASH_KEYS", "Failed to update sha256");
                return -1;
            }
        }
        if(wc_Sha256Final(sha256, commitment) != 0) {
            ESP_LOGE("HASH_KEYS", "Failed to finalise sha256");
            return -1;
        }
        sp_read_unsigned_bin(joint_key->commitment_hash, commitment, WC_SHA256_DIGEST_SIZE);
    }
    return 0;
}