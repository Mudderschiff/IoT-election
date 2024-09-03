#ifndef MODEL_H
#define MODEL_H

#include <wolfssl/wolfcrypt/port/Espressif/esp32-crypt.h>
#include <wolfssl/wolfcrypt/wolfmath.h>
#include <wolfssl/ssl.h>
#include "esp_log.h"
#include "esp_random.h"
#include "model.h"


int mod_exp(sp_int *g, sp_int *x, sp_int *p, sp_int *y);
void print_mp_int(sp_int *num);
int g_pow_p(sp_int *seckey, sp_int *pubkey);
int rand_q(sp_int *result);
int hash(sp_int *a, sp_int *b, sp_int *result);
int make_schnorr_proof(sp_int *pubkey, sp_int *seckey);

#endif // MOD_MATH_H