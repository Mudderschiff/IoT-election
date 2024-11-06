#ifndef UTILS_H
#define UTILS_H

#include <stdint.h>
#include <wolfssl/wolfcrypt/port/Espressif/esp32-crypt.h>
#include <wolfssl/wolfcrypt/wolfmath.h>
#include <wolfssl/ssl.h>
#include "crypto_utils.h" 

void int_to_bytes(int value, uint8_t *bytes);
void print_sp_int(sp_int *num);
void free_ElectionKeyPair(ElectionKeyPair *key_pair);
void free_ElectionPolynomial(ElectionPolynomial *polynomial);
void free_Coefficient(Coefficient *coefficient);
void free_SchnorrProof(SchnorrProof *proof);

#endif // UTILS_H