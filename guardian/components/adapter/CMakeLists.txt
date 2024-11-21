idf_component_register(SRCS "adapter.c" "util/serialize.c"
                    INCLUDE_DIRS "include" "util/include"
                    REQUIRES mqtt model protocol_examples_common json)
