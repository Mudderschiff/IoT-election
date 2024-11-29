#ifndef SERIALIZE_H
#define SERIALIZE_H

#include "crypto_utils.h"
#include "buff.pb-c.h"
#include <wolfssl/wolfcrypt/wolfmath.h>

uint8_t* serialize_election_partial_key_verification(ElectionPartialKeyVerification* verification, unsigned* len);
int deserialize_election_partial_key_verification(uint8_t* buffer, unsigned len, ElectionPartialKeyVerification* verification);
uint8_t* serialize_election_partial_key_backup(ElectionPartialKeyPairBackup* backup, unsigned* len);
int deserialize_election_partial_key_backup(uint8_t* buffer, unsigned len, ElectionPartialKeyPairBackup* backup);
uint8_t* serialize_election_key_pair(ElectionKeyPair* key_pair, unsigned* len);
int deserialize_election_key_pair(uint8_t* buffer, unsigned len, ElectionKeyPair* key_pair);


#endif // SERIALIZE_H


