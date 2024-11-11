#ifndef MODEL_H
#define MODEL_H


#include "utils.h"
#include "crypto_utils.h"
#include "model.h"

int generate_election_key_pair(int quorum, ElectionKeyPair *key_pair);
int generate_election_partial_key_backup(ElectionKeyPair *sender, ElectionKeyPair *receiver, ElectionPartialKeyPairBackup *backup);
int verify_election_partial_key_backup(ElectionKeyPair *receiver, ElectionKeyPair *sender, ElectionPartialKeyPairBackup *backup, ElectionPartialKeyVerification *verification);
#endif // MOD_MATH_H