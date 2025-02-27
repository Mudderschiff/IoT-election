idf_component_register(SRCS "main.c" "test_performance.c"
                    INCLUDE_DIRS "."
                    REQUIRES model adapter nvs_flash)
