set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DWOLFSSL_USER_SETTINGS")

idf_component_register(SRCS "model.c" "util/constants.c" "util/crypto_utils.c" "util/utils.c"
                    INCLUDE_DIRS "include" "util/include"
                    REQUIRES wolfssl)
