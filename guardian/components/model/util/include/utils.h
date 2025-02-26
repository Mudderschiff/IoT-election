#ifndef UTILS_H
#define UTILS_H

#include <stdint.h>
#include <wolfssl/wolfcrypt/port/Espressif/esp32-crypt.h>
#include <wolfssl/wolfcrypt/wolfmath.h>
#include <wolfssl/ssl.h>
#include "crypto_utils.h" 

void free_DecryptionShare(DecryptionShare* share);
void free_CiphertextTally(CiphertextTally* tally);
void free_CiphertextTallySelection(CiphertextTallySelection* selection);
void free_CiphertextTallyContest(CiphertextTallyContest* contest);
void free_ChaumPedersenProof(ChaumPedersenProof* proof);
void free_CiphertextDecryptionSelection(CiphertextDecryptionSelection* selection);
void free_CiphertextDecryptionContest(CiphertextDecryptionContest* contest);
void free_ElectionPartialKeyPairBackup(ElectionPartialKeyPairBackup* backup);
void free_ElectionKeyPair(ElectionKeyPair *key_pair);
void free_ElectionPolynomial(ElectionPolynomial *polynomial);
void free_Coefficient(Coefficient *coefficient);
void free_SchnorrProof(SchnorrProof *proof);

#endif // UTILS_H