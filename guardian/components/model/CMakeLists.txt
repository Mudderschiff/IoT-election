set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DWOLFSSL_USER_SETTINGS")

idf_component_register(SRCS "model.c"
                    INCLUDE_DIRS "include"
                    REQUIRES wolfssl)
