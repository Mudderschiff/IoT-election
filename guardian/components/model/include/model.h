#ifndef MODEL_H
#define MODEL_H


#include "utils.h"
#include "crypto_utils.h"
#include "model.h"

int generate_election_key_pair(int quorum, ElectionKeyPair *key_pair);
int generate_election_partial_key_backup(int sender_guardian_id, int designated_id, ElectionPolynomial *sender_guardian_polynomial, sp_int *receiver_guardian_public_key, ElectionPartialKeyPairBackup *backup);
int verify_election_partial_key_backup(ElectionKeyPair *guardian, ElectionKeyPair *designated, ElectionPartialKeyPairBackup *backup, ElectionKeyPair *key_pair);

#endif // MOD_MATH_H