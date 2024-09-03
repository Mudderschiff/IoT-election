#include "model.h"
#include "freertos/task.h"
#include "freertos/FreeRTOS.h"

void app_main(void) {
    DECL_MP_INT_SIZE(seckey, 256);
    DECL_MP_INT_SIZE(pubkey, 3072);
    NEW_MP_INT_SIZE(seckey, 256, NULL, DYNAMIC_TYPE_BIGINT);
    NEW_MP_INT_SIZE(pubkey, 3072, NULL, DYNAMIC_TYPE_BIGINT);
    INIT_MP_INT_SIZE(seckey, 256);
    INIT_MP_INT_SIZE(pubkey, 3072);
    rand_q(seckey);
    g_pow_p(seckey, pubkey);
    make_schnorr_proof(seckey, pubkey);
    
    
    //Clear
    sp_zero(seckey);
    sp_zero(pubkey);
    FREE_MP_INT_SIZE(seckey, NULL, DYNAMIC_TYPE_BIGINT);
    FREE_MP_INT_SIZE(pubkey, NULL, DYNAMIC_TYPE_BIGINT);
}