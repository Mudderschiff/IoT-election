#ifndef MODEL_H
#define MODEL_H


#include "utils.h"
#include "crypto_utils.h"
#include "model.h"

int combine_election_public_keys(ElectionKeyPair *guardian, ElectionKeyPair *pubkey_map, size_t count, ElectionJointKey *joint_key);
int generate_election_key_pair(int quorum, ElectionKeyPair *key_pair);
int generate_election_partial_key_backup(ElectionKeyPair *sender, ElectionKeyPair *receiver, ElectionPartialKeyPairBackup *backup);
int verify_election_partial_key_backup(ElectionKeyPair *receiver, ElectionKeyPair *sender, ElectionPartialKeyPairBackup *backup, ElectionPartialKeyVerification *verification);
int compute_decryption_share(ElectionKeyPair *guardian, CiphertextTally *ciphertally, DecryptionShare *share);
#endif // MOD_MATH_H