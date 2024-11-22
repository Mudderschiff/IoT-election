#ifndef CJSON_H
#define CJSON_H

#include "cJSON.h"
#include "crypto_utils.h"

char* serialize_election_key_pair(ElectionKeyPair* key_pair);
char* serialize_election_partial_key_backup(ElectionPartialKeyPairBackup* backup);
char* serialize_election_partial_key_verification(ElectionPartialKeyVerification* verification);

#endif // CJSON_H


