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
    char *buffer = (char *)malloc(size * 2 + 1);
    if (buffer == NULL) {
        ESP_LOGE("Print mp_int", "Failed to allocate memory for buffer");
        return;
    }
    memset(buffer, 0, size * 2 + 1); // Initialize the buffer to zeros

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
    char buffer[size * 3 + 1]; // Each byte will be represented by 2 hex digits and a space
    for (int i = 0; i < size; i++) {
        sprintf(&buffer[i * 3], "%02x ", array[i]);
    }
    buffer[size * 3] = '\0'; // Null-terminate the string
    ESP_LOGI("BYTE_ARRAY", "%s", buffer);
}

/**
 * @brief Key derivation function
 * @param salt: Salt used for the hashing
 * @param message: Message to be hashed
 * @param encrypted_message: Write Encrypted message back to encrypted_message
 * @return 0 on success, 1 on failure
 */
int kdf(sp_int *salt, sp_int *message, sp_int *encrypted_message) {
    // pad the message if it's not a multiple of 32 (BLOCK_SIZE)
    byte *salt_bytes = (byte *)malloc(sp_unsigned_bin_size(salt));
    if(salt_bytes == NULL) {
        ESP_LOGE("KDF", "Failed to allocate memory for salt_bytes");
        return 1;
    }
    sp_to_unsigned_bin(salt, salt_bytes);
    int message_len = sp_unsigned_bin_size(message);
    int remainder = message_len % BLOCK_SIZE;
    int padded_size = (remainder == 0) ? message_len : (message_len + (BLOCK_SIZE - remainder));
    byte *padded_message = (byte *)malloc(padded_size);
    if(padded_message == NULL) {
        ESP_LOGE("KDF", "Failed to allocate memory for padded_message");
        return 1;
    }
    memset(padded_message, 0, padded_size);
    sp_to_unsigned_bin_at_pos(0, message, padded_message);

    byte *fixed_message = (byte *)malloc(MODIFIED_CHUNK_SIZE);
    if(fixed_message == NULL) {
        ESP_LOGE("KDF", "Failed to allocate memory for fixed_message");
        return 1;
    }
    byte *data_key = (byte *)malloc(BLOCK_SIZE);
    if(data_key == NULL) {
        ESP_LOGE("KDF", "Failed to allocate memory for data_key");
        return 1;
    }
    // add message size at the end of the message
    int_to_bytes(padded_size, &fixed_message[MODIFIED_CHUNK_SIZE - 4]);
    for(int i = 0; i < padded_size; i += BLOCK_SIZE) {
        // add the block number to the message
        int_to_bytes(i / BLOCK_SIZE, fixed_message);
        memcpy(fixed_message + 4, padded_message + i, BLOCK_SIZE);
        get_hmac(salt_bytes, fixed_message, data_key);
        for(int j = 0; j < BLOCK_SIZE; j++) {
            padded_message[i + j] ^= data_key[j];
        }
    }
    sp_read_unsigned_bin(encrypted_message, padded_message, padded_size);
    free(padded_message);
    free(fixed_message);
    free(data_key);
    free(salt_bytes);
    return 0;
}

/** 
 * @brief Compute Large number Modular Exponetiation with hardware Y = (G ^ X) mod P
 * @param g: Base
 * @param x: Exponent
 * @param p: Modulus
 * @param y: Result
 * @return 0 on success, -1 on failure
 */
int powmod(sp_int *g, sp_int *x, sp_int *p, sp_int *y) {
    return esp_mp_exptmod(g,x,p,y);
}

/**
 * @brief Compute Large number Modular Exponetiation with known G (generator also known as base) and P (large prime also known as modulus). Y = (G ^ X) mod P
 * @param seckey: Exponent
 * @param pubkey: Result
 * @return 0 on success, -1 on failure
 */
int g_pow_p(sp_int *seckey, sp_int *pubkey) {
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
    sp_zero(large_prime);
    sp_zero(generator);
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
int rand_q(mp_int *result) {
    int sz = 32;    
    unsigned char *block = (unsigned char *)malloc(sz * sizeof(unsigned char));
    if (block == NULL) {
        ESP_LOGE("RAND_Q", "Failed to allocate memory for block");
        return -1; // Memory allocation failed
    }  

    esp_fill_random(block, sz);
    sp_read_unsigned_bin(result, block, sz);
    // Possible optimization might not clear the random number
    memset(block, 0, sz); 
    free(block);

    DECL_MP_INT_SIZE(small_prime, 256);
    NEW_MP_INT_SIZE(small_prime, 256, NULL, DYNAMIC_TYPE_BIGINT);
    INIT_MP_INT_SIZE(small_prime, 256);
    sp_read_unsigned_bin(small_prime, q_256, sizeof(q_256));

    sp_mod(result, small_prime, result);

    // Clear
    sp_zero(small_prime);
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
    ret = sp_to_unsigned_bin(a, tmp);
    ret = sp_to_unsigned_bin_at_pos(a_size,b, tmp);

    // Conveniencefunction. Handles Initialisation, Update and Finalisation
    if ((ret = wc_Sha256Hash(tmp, tmp_size, tmp)) != 0) {
        WOLFSSL_MSG("Hashing Failed");
        return ret;
    }

    ret = sp_read_unsigned_bin(result, tmp, WC_SHA256_DIGEST_SIZE);   
    memset(tmp, 0, tmp_size);
    free(tmp);
    return ret;
}


/**
 * @brief Computes a single coordinate value of the election polynomial used for sharing
 * @param exponent_modifier: Unique modifier (usually sequence order) for exponent [0, Q]
 * @param polynomial: Election polynomial
 * @param coordinate: The computed coordinate
 * @return 0 on success, -1 on failure
 */
int compute_polynomial_coordinate(int exponent_modifier, ElectionPolynomial polynomial, sp_int *coordinate) {
    DECL_MP_INT_SIZE(modifier, 64);
    NEW_MP_INT_SIZE(modifier, 64, NULL, DYNAMIC_TYPE_BIGINT);
    INIT_MP_INT_SIZE(modifier, 64);
    sp_set_int(modifier, exponent_modifier);

    DECL_MP_INT_SIZE(exponent_i, 64);
    NEW_MP_INT_SIZE(exponent_i, 64, NULL, DYNAMIC_TYPE_BIGINT);
    INIT_MP_INT_SIZE(exponent_i, 64);

    DECL_MP_INT_SIZE(exponent, 256);
    NEW_MP_INT_SIZE(exponent, 256, NULL, DYNAMIC_TYPE_BIGINT);
    INIT_MP_INT_SIZE(exponent, 256);
    sp_zero(exponent);

    DECL_MP_INT_SIZE(factor, 256);
    NEW_MP_INT_SIZE(factor, 256, NULL, DYNAMIC_TYPE_BIGINT);
    INIT_MP_INT_SIZE(factor, 256);
    sp_zero(factor);

    DECL_MP_INT_SIZE(small_prime, 256);
    NEW_MP_INT_SIZE(small_prime, 256, NULL, DYNAMIC_TYPE_BIGINT);
    INIT_MP_INT_SIZE(small_prime, 256);
    sp_read_unsigned_bin(small_prime, q_256, sizeof(q_256));
    for (size_t i = 0; i < polynomial.num_coefficients; i++)
    {   
        sp_set_int(exponent_i, i);
        // Not Accelerated. Operator lenght to small
        sp_exptmod(modifier, exponent_i, small_prime, exponent);
        sp_mulmod(polynomial.coefficients[i].value, exponent, small_prime, factor);
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
int verify_polynomial_coordinate(int exponent_modifier, ElectionPolynomial polynomial, sp_int *coordinate) {
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
    sp_set_int(modifier, exponent_modifier);

    for(size_t i = 0; i < polynomial.num_coefficients; i++) {
        sp_set_int(exponent_i, i);
        sp_exptmod(modifier, exponent_i, large_prime, exponent);
        sp_exptmod(polynomial.coefficients[i].commitment, exponent, large_prime, factor);
        sp_mulmod(commitment_output, factor, large_prime, commitment_output);
    }
    g_pow_p(coordinate, value_output);
    ESP_LOGI("VERIFY_POLYNOMIAL", "Value output");
    print_sp_int(value_output);
    ESP_LOGI("VERIFY_POLYNOMIAL", "Commitment output");
    print_sp_int(commitment_output);
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

    g_pow_p(nonce, encrypted_message->pad); //alpha
    sp_exptmod(public_key, nonce, large_prime, pubkey_pow_n); //beta
    FREE_MP_INT_SIZE(large_prime, NULL, DYNAMIC_TYPE_BIGINT);
    hash(encrypted_message->pad, pubkey_pow_n, session_key);
    FREE_MP_INT_SIZE(pubkey_pow_n, NULL, DYNAMIC_TYPE_BIGINT);

    kdf(session_key, message, encrypted_message->data);

    int message_size = sp_unsigned_bin_size(encrypted_message->data);
    int seed_size = sp_unsigned_bin_size(encryption_seed);
    // Pad the seed with 0 and add the message size at the end
    byte *padded_seed = (byte *)malloc(seed_size + 8);
    if (padded_seed == NULL) {
        ESP_LOGE("PADDED_COORDINATE", "Failed to allocate memory for padded_seed");
        return 1;
    }
    int_to_bytes(0,padded_seed);
    sp_to_unsigned_bin_at_pos(4, encryption_seed, padded_seed);
    int_to_bytes(message_size, &padded_seed[(seed_size + 4)]);

    byte *tmp = (byte *)malloc(BLOCK_SIZE);
    if (tmp == NULL) {
        ESP_LOGE("PADDED_COORDINATE", "Failed to allocate memory for mac_key");
        return 1;
    }
    byte *key = (byte *)malloc(BLOCK_SIZE);
    if (key == NULL) {
        ESP_LOGE("PADDED_COORDINATE", "Failed to allocate memory for key");
        return 1;
    }
    sp_to_unsigned_bin(session_key, key);
    get_hmac(key, padded_seed, tmp);
    free(key);
    free(padded_seed);
    byte *to_mac = (byte *)malloc(sp_unsigned_bin_size(encrypted_message->pad) + sp_unsigned_bin_size(encrypted_message->data));
    if (to_mac == NULL) {
        ESP_LOGE("PADDED_COORDINATE", "Failed to allocate memory for to_mac");
        return 1;
    }
    sp_to_unsigned_bin_at_pos(0, encrypted_message->pad, to_mac);
    sp_to_unsigned_bin_at_pos(sp_unsigned_bin_size(encrypted_message->pad), encrypted_message->data, to_mac);
    // init to_mac & mac
    get_hmac(tmp, to_mac, tmp);
    sp_read_unsigned_bin(encrypted_message->mac, tmp, BLOCK_SIZE);
    print_sp_int(encrypted_message->pad);
    print_sp_int(encrypted_message->data);
    print_sp_int(encrypted_message->mac);
    free(to_mac);
    free(tmp);
    return 0;
}

/**
 * Decrypt an ElGamal ciphertext using a known ElGamal secret key
 * @param secret_key: The corresponding ElGamal secret key.
 * @param encryption_seed: Encryption seed (Q) for election.
 * @param plaintext: Decrypted plaintext message.
 */
int hashed_elgamal_decrypt(HashedElGamalCiphertext *encrypted_message, sp_int *secret_key, sp_int *encryption_seed, sp_int *message) {
    /*

        session_key = hash_elems(self.pad, pow_p(self.pad, secret_key))
        data_bytes = to_padded_bytes(self.data)

        (ciphertext_chunks, bit_length) = _get_chunks(data_bytes)
        mac_key = get_hmac(
            session_key.to_hex_bytes(),
            encryption_seed.to_hex_bytes(),
            bit_length,
        )
        to_mac = self.pad.to_hex_bytes() + data_bytes
        mac = bytes_to_hex(get_hmac(mac_key, to_mac))

        if mac != self.mac:
            log_error("MAC verification failed in decryption.")
            return None

        data = b""
        for i, block in enumerate(ciphertext_chunks):
            data_key = get_hmac(
                session_key.to_hex_bytes(),
                encryption_seed.to_hex_bytes(),
                bit_length,
                (i + 1),
            )
            data += bytes([a ^ b for (a, b) in zip(block, data_key)])
        return data
    */
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
        polynomial->coefficients[i].value = (sp_int*)XMALLOC(MP_INT_SIZEOF(MP_BITS_CNT(256)), NULL, DYNAMIC_TYPE_BIGINT);
        polynomial->coefficients[i].commitment = (sp_int*)XMALLOC(MP_INT_SIZEOF(MP_BITS_CNT(3072)), NULL, DYNAMIC_TYPE_BIGINT);
        
        if (polynomial->coefficients[i].value) {
            XMEMSET(polynomial->coefficients[i].value, 0, MP_INT_SIZEOF(MP_BITS_CNT(256)));
            mp_init_size(polynomial->coefficients[i].value, MP_BITS_CNT(256));
        }
        if (polynomial->coefficients[i].commitment) {
            XMEMSET(polynomial->coefficients[i].commitment, 0, MP_INT_SIZEOF(MP_BITS_CNT(3072)));
            mp_init_size(polynomial->coefficients[i].commitment, MP_BITS_CNT(3072));
        }
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
 * @brief Given an ElGamal keypair and a nonce, generates a proof that the prover knows the secret key without revealing it.
 * @param seckey: The secret key
 * @param pubkey: The public key
 * @param nonce: A random element in [0,Q)
 * @param proof: The Schnorr proof
 * @return 0 on success, -1 on failure
 */
int make_schnorr_proof(sp_int *seckey, sp_int *pubkey, sp_int *nonce, SchnorrProof *proof) {
    proof->pubkey = (sp_int*)XMALLOC(MP_INT_SIZEOF(MP_BITS_CNT(3072)), NULL, DYNAMIC_TYPE_BIGINT);
    proof->commitment = (sp_int*)XMALLOC(MP_INT_SIZEOF(MP_BITS_CNT(3072)), NULL, DYNAMIC_TYPE_BIGINT);
    proof->challenge = (sp_int*)XMALLOC(MP_INT_SIZEOF(MP_BITS_CNT(256)), NULL, DYNAMIC_TYPE_BIGINT);
    proof->response = (sp_int*)XMALLOC(MP_INT_SIZEOF(MP_BITS_CNT(4096)), NULL, DYNAMIC_TYPE_BIGINT);

    if (proof->pubkey != NULL) {
        XMEMSET(proof->pubkey, 0, MP_INT_SIZEOF(MP_BITS_CNT(3072)));
    }
    if (proof->commitment != NULL) {
        XMEMSET(proof->commitment, 0, MP_INT_SIZEOF(MP_BITS_CNT(3072)));
    }
    if (proof->challenge != NULL) {
        XMEMSET(proof->challenge, 0, MP_INT_SIZEOF(MP_BITS_CNT(256)));
    }
    if (proof->response != NULL) {
        XMEMSET(proof->response, 0, MP_INT_SIZEOF(MP_BITS_CNT(4096)));
    }

    mp_init_size(proof->pubkey, MP_BITS_CNT(3072));
    mp_init_size(proof->commitment, MP_BITS_CNT(3072));
    mp_init_size(proof->challenge, MP_BITS_CNT(256));
    mp_init_size(proof->response, MP_BITS_CNT(4096));

    sp_copy(pubkey, proof->pubkey);
    g_pow_p(nonce, proof->commitment);
    hash(pubkey, proof->commitment, proof->challenge);

    // a + bc ^ q = nonce + seckey * challenge ^ q
    DECL_MP_INT_SIZE(q, 256);
    NEW_MP_INT_SIZE(q, 256, NULL, DYNAMIC_TYPE_BIGINT);
    INIT_MP_INT_SIZE(q, 256);
    sp_read_unsigned_bin(q, q_256, sizeof(q_256));

    sp_mul(seckey,proof->challenge,proof->response);
    sp_addmod(nonce,proof->response,q,proof->response);

    sp_zero(q);
    FREE_MP_INT_SIZE(q, NULL, DYNAMIC_TYPE_BIGINT);
    return 0;
}
