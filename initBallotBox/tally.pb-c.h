/* Generated by the protocol buffer compiler.  DO NOT EDIT! */
/* Generated from: tally.proto */

#ifndef PROTOBUF_C_tally_2eproto__INCLUDED
#define PROTOBUF_C_tally_2eproto__INCLUDED

#include <protobuf-c/protobuf-c.h>

PROTOBUF_C__BEGIN_DECLS

#if PROTOBUF_C_VERSION_NUMBER < 1000000
# error This file was generated by a newer version of protoc-c which is incompatible with your libprotobuf-c headers. Please update your headers.
#elif 1004001 < PROTOBUF_C_MIN_COMPILER_VERSION
# error This file was generated by an older version of protoc-c which is incompatible with your libprotobuf-c headers. Please regenerate this file with a newer version of protoc-c.
#endif


typedef struct CiphertextTallySelectionProto CiphertextTallySelectionProto;
typedef struct CiphertextTallySelectionsProto CiphertextTallySelectionsProto;
typedef struct CiphertextDecryptionSelectionProto CiphertextDecryptionSelectionProto;
typedef struct CiphertextDecryptionContestProto CiphertextDecryptionContestProto;


/* --- enums --- */


/* --- messages --- */

struct  CiphertextTallySelectionProto
{
  ProtobufCMessage base;
  char *object_id;
  ProtobufCBinaryData description_hash;
  ProtobufCBinaryData ciphertext_pad;
  ProtobufCBinaryData ciphertext_data;
};
#define CIPHERTEXT_TALLY_SELECTION_PROTO__INIT \
 { PROTOBUF_C_MESSAGE_INIT (&ciphertext_tally_selection_proto__descriptor) \
    , NULL, {0,NULL}, {0,NULL}, {0,NULL} }


struct  CiphertextTallySelectionsProto
{
  ProtobufCMessage base;
  ProtobufCBinaryData base_hash;
  int32_t num_selections;
  size_t n_selections;
  CiphertextTallySelectionProto **selections;
};
#define CIPHERTEXT_TALLY_SELECTIONS_PROTO__INIT \
 { PROTOBUF_C_MESSAGE_INIT (&ciphertext_tally_selections_proto__descriptor) \
    , {0,NULL}, 0, 0,NULL }


struct  CiphertextDecryptionSelectionProto
{
  ProtobufCMessage base;
  char *object_id;
  ProtobufCBinaryData guardian_id;
  ProtobufCBinaryData share;
  ProtobufCBinaryData proof_pad;
  ProtobufCBinaryData proof_data;
  ProtobufCBinaryData proof_challenge;
  ProtobufCBinaryData proof_response;
};
#define CIPHERTEXT_DECRYPTION_SELECTION_PROTO__INIT \
 { PROTOBUF_C_MESSAGE_INIT (&ciphertext_decryption_selection_proto__descriptor) \
    , NULL, {0,NULL}, {0,NULL}, {0,NULL}, {0,NULL}, {0,NULL}, {0,NULL} }


struct  CiphertextDecryptionContestProto
{
  ProtobufCMessage base;
  ProtobufCBinaryData guardian_id;
  ProtobufCBinaryData description_hash;
  int32_t num_selections;
  size_t n_selections;
  CiphertextDecryptionSelectionProto **selections;
};
#define CIPHERTEXT_DECRYPTION_CONTEST_PROTO__INIT \
 { PROTOBUF_C_MESSAGE_INIT (&ciphertext_decryption_contest_proto__descriptor) \
    , {0,NULL}, {0,NULL}, 0, 0,NULL }


/* CiphertextTallySelectionProto methods */
void   ciphertext_tally_selection_proto__init
                     (CiphertextTallySelectionProto         *message);
size_t ciphertext_tally_selection_proto__get_packed_size
                     (const CiphertextTallySelectionProto   *message);
size_t ciphertext_tally_selection_proto__pack
                     (const CiphertextTallySelectionProto   *message,
                      uint8_t             *out);
size_t ciphertext_tally_selection_proto__pack_to_buffer
                     (const CiphertextTallySelectionProto   *message,
                      ProtobufCBuffer     *buffer);
CiphertextTallySelectionProto *
       ciphertext_tally_selection_proto__unpack
                     (ProtobufCAllocator  *allocator,
                      size_t               len,
                      const uint8_t       *data);
void   ciphertext_tally_selection_proto__free_unpacked
                     (CiphertextTallySelectionProto *message,
                      ProtobufCAllocator *allocator);
/* CiphertextTallySelectionsProto methods */
void   ciphertext_tally_selections_proto__init
                     (CiphertextTallySelectionsProto         *message);
size_t ciphertext_tally_selections_proto__get_packed_size
                     (const CiphertextTallySelectionsProto   *message);
size_t ciphertext_tally_selections_proto__pack
                     (const CiphertextTallySelectionsProto   *message,
                      uint8_t             *out);
size_t ciphertext_tally_selections_proto__pack_to_buffer
                     (const CiphertextTallySelectionsProto   *message,
                      ProtobufCBuffer     *buffer);
CiphertextTallySelectionsProto *
       ciphertext_tally_selections_proto__unpack
                     (ProtobufCAllocator  *allocator,
                      size_t               len,
                      const uint8_t       *data);
void   ciphertext_tally_selections_proto__free_unpacked
                     (CiphertextTallySelectionsProto *message,
                      ProtobufCAllocator *allocator);
/* CiphertextDecryptionSelectionProto methods */
void   ciphertext_decryption_selection_proto__init
                     (CiphertextDecryptionSelectionProto         *message);
size_t ciphertext_decryption_selection_proto__get_packed_size
                     (const CiphertextDecryptionSelectionProto   *message);
size_t ciphertext_decryption_selection_proto__pack
                     (const CiphertextDecryptionSelectionProto   *message,
                      uint8_t             *out);
size_t ciphertext_decryption_selection_proto__pack_to_buffer
                     (const CiphertextDecryptionSelectionProto   *message,
                      ProtobufCBuffer     *buffer);
CiphertextDecryptionSelectionProto *
       ciphertext_decryption_selection_proto__unpack
                     (ProtobufCAllocator  *allocator,
                      size_t               len,
                      const uint8_t       *data);
void   ciphertext_decryption_selection_proto__free_unpacked
                     (CiphertextDecryptionSelectionProto *message,
                      ProtobufCAllocator *allocator);
/* CiphertextDecryptionContestProto methods */
void   ciphertext_decryption_contest_proto__init
                     (CiphertextDecryptionContestProto         *message);
size_t ciphertext_decryption_contest_proto__get_packed_size
                     (const CiphertextDecryptionContestProto   *message);
size_t ciphertext_decryption_contest_proto__pack
                     (const CiphertextDecryptionContestProto   *message,
                      uint8_t             *out);
size_t ciphertext_decryption_contest_proto__pack_to_buffer
                     (const CiphertextDecryptionContestProto   *message,
                      ProtobufCBuffer     *buffer);
CiphertextDecryptionContestProto *
       ciphertext_decryption_contest_proto__unpack
                     (ProtobufCAllocator  *allocator,
                      size_t               len,
                      const uint8_t       *data);
void   ciphertext_decryption_contest_proto__free_unpacked
                     (CiphertextDecryptionContestProto *message,
                      ProtobufCAllocator *allocator);
/* --- per-message closures --- */

typedef void (*CiphertextTallySelectionProto_Closure)
                 (const CiphertextTallySelectionProto *message,
                  void *closure_data);
typedef void (*CiphertextTallySelectionsProto_Closure)
                 (const CiphertextTallySelectionsProto *message,
                  void *closure_data);
typedef void (*CiphertextDecryptionSelectionProto_Closure)
                 (const CiphertextDecryptionSelectionProto *message,
                  void *closure_data);
typedef void (*CiphertextDecryptionContestProto_Closure)
                 (const CiphertextDecryptionContestProto *message,
                  void *closure_data);

/* --- services --- */


/* --- descriptors --- */

extern const ProtobufCMessageDescriptor ciphertext_tally_selection_proto__descriptor;
extern const ProtobufCMessageDescriptor ciphertext_tally_selections_proto__descriptor;
extern const ProtobufCMessageDescriptor ciphertext_decryption_selection_proto__descriptor;
extern const ProtobufCMessageDescriptor ciphertext_decryption_contest_proto__descriptor;

PROTOBUF_C__END_DECLS


#endif  /* PROTOBUF_C_tally_2eproto__INCLUDED */
