idf_component_register(SRCS "adapter.c" "util/serialize.c" "util/buff.pb-c.c" "util/tally.pb-c.c" "util/test_decrypt.c"
                    INCLUDE_DIRS "include" "util/include"
                    REQUIRES mqtt model protocol_examples_common protobuf-c)
