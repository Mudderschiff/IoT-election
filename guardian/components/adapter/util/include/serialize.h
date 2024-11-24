#ifndef SERIALIZE_H
#define SERIALIZE_H

#include "crypto_utils.h"
#include "buff.pb-c.h"

uint8_t* serialize_election_partial_key_verification(ElectionPartialKeyVerification* verification, unsigned* len);
int deserialize_election_partial_key_verification(uint8_t* buffer, unsigned len, ElectionPartialKeyVerification* verification);
int deserialize_election_partial_key_backup(uint8_t* buffer, unsigned len, ElectionPartialKeyPairBackup* backup);
uint8_t* serialize_election_partial_key_backup(ElectionPartialKeyPairBackup* backup, unsigned* len);


#endif // SERIALIZE_H


