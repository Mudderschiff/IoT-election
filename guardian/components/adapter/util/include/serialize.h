#ifndef SERIALIZE_H
#define SERIALIZE_H

#include "crypto_utils.h"
#include "buff.pb-c.h"
#include "tally.pb-c.h"
#include <wolfssl/wolfcrypt/wolfmath.h>


uint8_t* serialize_election_partial_key_verification(ElectionPartialKeyVerification* verification, unsigned* len);
uint8_t* serialize_election_partial_key_backup(ElectionPartialKeyPairBackup* backup, unsigned* len);
uint8_t* serialize_election_key_pair(ElectionKeyPair* key_pair, unsigned* len);
uint8_t* serialize_DecryptionShare(DecryptionShare* share, unsigned* len);

int deserialize_election_partial_key_verification(uint8_t* buffer, unsigned len, ElectionPartialKeyVerification* verification);
int deserialize_election_partial_key_backup(uint8_t* buffer, unsigned len, ElectionPartialKeyPairBackup* backup);
int deserialize_election_key_pair(uint8_t* buffer, unsigned len, ElectionKeyPair* key_pair);
int deserialize_ciphertext_tally(uint8_t *buffer, unsigned len, CiphertextTally* ciphertally);

#endif // SERIALIZE_H


