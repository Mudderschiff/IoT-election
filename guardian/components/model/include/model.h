#ifndef MODEL_H
#define MODEL_H


#include "utils.h"
#include "crypto_utils.h"
#include "model.h"

int generate_election_key_pair(int quorum, ElectionKeyPair *key_pair);
int generate_election_partial_key_backup(int guardian_id, ElectionPolynomial own_polynomial, sp_int *sender_public_key);
//int verify_election_partial_key_backup(int guardian_id, ElectionPartialKeyBackup *backup, ElectionKeyPair *key_pair);


#endif // MOD_MATH_H