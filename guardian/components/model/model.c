#include "model.h"
#include "esp_heap_caps.h"

/**
 * @brief Generates election key pair, proof, and polynomial
 * @param quorum: The number of guardians required to decrypt the election
 * @param key_pair: The election key pair
 * @return 0 on success, -1 on failure
 */
int generate_election_key_pair(int quorum, ElectionKeyPair *key_pair) {
    key_pair->public_key = NULL;
    NEW_MP_INT_SIZE(key_pair->public_key, 3072, NULL, DYNAMIC_TYPE_BIGINT);
    INIT_MP_INT_SIZE(key_pair->public_key, 3072);

    key_pair->private_key = NULL;
    NEW_MP_INT_SIZE(key_pair->private_key, 256, NULL, DYNAMIC_TYPE_BIGINT);
    INIT_MP_INT_SIZE(key_pair->private_key, 256);
    
    key_pair->polynomial.num_coefficients = quorum;
    key_pair->polynomial.coefficients = (Coefficient*)XMALLOC(quorum * sizeof(Coefficient), NULL, DYNAMIC_TYPE_BIGINT);
    if (key_pair->polynomial.coefficients == NULL) {
        ESP_LOGE("Generate Election Key Pair", "Failed to allocate memory for coefficients");
        return -1;
    }
    generate_polynomial(&key_pair->polynomial);
    sp_copy(key_pair->polynomial.coefficients[0].value, key_pair->private_key);
    sp_copy(key_pair->polynomial.coefficients[0].commitment, key_pair->public_key);
    return 0;
}

/**
 * @brief Generate election partal key backup for sharing
 * @param sender_guardian_id: Owner of election key
 * @param sender_guardian_polynomial: The owner's Election polynomial
 * @param receiver_guardian_public_key: The receiving guardian's public key
 * @return PartialKeyBackup / Encrypted Coordinate
 */
int generate_election_partial_key_backup(ElectionKeyPair *sender, ElectionKeyPair *receiver, ElectionPartialKeyPairBackup *backup) {
    DECL_MP_INT_SIZE(coordinate, 256);
    NEW_MP_INT_SIZE(coordinate, 256, NULL, DYNAMIC_TYPE_BIGINT);
    INIT_MP_INT_SIZE(coordinate, 256);

    DECL_MP_INT_SIZE(nonce, 256);
    NEW_MP_INT_SIZE(nonce, 256, NULL, DYNAMIC_TYPE_BIGINT);
    INIT_MP_INT_SIZE(nonce, 256);

    DECL_MP_INT_SIZE(seed, 256);
    NEW_MP_INT_SIZE(seed, 256, NULL, DYNAMIC_TYPE_BIGINT);
    INIT_MP_INT_SIZE(seed, 256);

    DECL_MP_INT_SIZE(id, 48);
    NEW_MP_INT_SIZE(id, 48, NULL, DYNAMIC_TYPE_BIGINT);
    INIT_MP_INT_SIZE(id, 48);
    sp_read_unsigned_bin(id, receiver->guardian_id, sizeof(receiver->guardian_id));

    memcpy(backup->sender, sender->guardian_id, sizeof(sender->guardian_id));
    memcpy(backup->receiver, receiver->guardian_id, sizeof(receiver->guardian_id));

    backup->encrypted_coordinate.pad = NULL;
    NEW_MP_INT_SIZE(backup->encrypted_coordinate.pad, 3072, NULL, DYNAMIC_TYPE_BIGINT);
    INIT_MP_INT_SIZE(backup->encrypted_coordinate.pad, 3072);

    backup->encrypted_coordinate.data = NULL;
    NEW_MP_INT_SIZE(backup->encrypted_coordinate.data, 256, NULL, DYNAMIC_TYPE_BIGINT);
    INIT_MP_INT_SIZE(backup->encrypted_coordinate.data, 256);

    backup->encrypted_coordinate.mac = NULL;
    NEW_MP_INT_SIZE(backup->encrypted_coordinate.mac, 256, NULL, DYNAMIC_TYPE_BIGINT);
    INIT_MP_INT_SIZE(backup->encrypted_coordinate.mac, 256);

    compute_polynomial_coordinate(receiver->guardian_id, &sender->polynomial, coordinate);
    rand_q(nonce);
    hash(id, id, seed);
    hashed_elgamal_encrypt(coordinate, nonce, receiver->public_key, seed, &backup->encrypted_coordinate);
    sp_zero(nonce);
    sp_zero(seed);
    FREE_MP_INT_SIZE(coordinate, NULL, DYNAMIC_TYPE_BIGINT);
    FREE_MP_INT_SIZE(nonce, NULL, DYNAMIC_TYPE_BIGINT);
    FREE_MP_INT_SIZE(seed, NULL, DYNAMIC_TYPE_BIGINT);
    FREE_MP_INT_SIZE(id, NULL, DYNAMIC_TYPE_BIGINT);
    return 0;
}

/**
 * @brief Verify election partial key backup contain point on owners polynomial
 * @param guardian_id: Receiving guardian's identifier
 * @param sender_guardian_backup: Sender guardian's election partial key backup
 * @param sender_guardian_public_key: Sender guardian's election public key
 * @param receiver_guardian_keys: Receiving guardian's key pair
 */
int verify_election_partial_key_backup(ElectionKeyPair *receiver, ElectionKeyPair *sender, ElectionPartialKeyPairBackup *backup, ElectionPartialKeyVerification *verification) {
    DECL_MP_INT_SIZE(encryption_seed, 256);
    NEW_MP_INT_SIZE(encryption_seed, 256, NULL, DYNAMIC_TYPE_BIGINT);
    INIT_MP_INT_SIZE(encryption_seed, 256);

    DECL_MP_INT_SIZE(coordinate, 3072);
    NEW_MP_INT_SIZE(coordinate, 3072, NULL, DYNAMIC_TYPE_BIGINT);
    INIT_MP_INT_SIZE(coordinate, 3072);

    DECL_MP_INT_SIZE(gid, 48);
    NEW_MP_INT_SIZE(gid, 48, NULL, DYNAMIC_TYPE_BIGINT);
    INIT_MP_INT_SIZE(gid, 48);
    DECL_MP_INT_SIZE(bid, 48);
    NEW_MP_INT_SIZE(bid, 48, NULL, DYNAMIC_TYPE_BIGINT);
    INIT_MP_INT_SIZE(bid, 48);
    sp_read_unsigned_bin(gid, receiver->guardian_id, sizeof(receiver->guardian_id));
    sp_read_unsigned_bin(bid, backup->receiver, sizeof(backup->receiver));
    
    memcpy(verification->sender, backup->sender, sizeof(backup->sender));
    memcpy(verification->receiver, backup->receiver, sizeof(backup->receiver));
    memcpy(verification->verifier, receiver->guardian_id, sizeof(receiver->guardian_id));
    verification->verified = false;
    //get_backup_seed()
    hash(gid, bid, encryption_seed);
    // decrypt encrypted_coordinate
    hashed_elgamal_decrypt(&backup->encrypted_coordinate, receiver->private_key, encryption_seed, coordinate);
    verification->verified = verify_polynomial_coordinate(backup->receiver, &sender->polynomial, coordinate);

    sp_zero(encryption_seed);
    FREE_MP_INT_SIZE(encryption_seed, NULL, DYNAMIC_TYPE_BIGINT);
    FREE_MP_INT_SIZE(coordinate, NULL, DYNAMIC_TYPE_BIGINT);
    FREE_MP_INT_SIZE(gid, NULL, DYNAMIC_TYPE_BIGINT);
    FREE_MP_INT_SIZE(bid, NULL, DYNAMIC_TYPE_BIGINT);
    return 0;
}

int combine_election_public_keys(ElectionKeyPair *guardian, ElectionKeyPair *pubkey_map, size_t count, ElectionJointKey *joint_key) {
    joint_key->joint_key = NULL;
    NEW_MP_INT_SIZE(joint_key->joint_key, 3072, NULL, DYNAMIC_TYPE_BIGINT);
    INIT_MP_INT_SIZE(joint_key->joint_key, 3072);
    joint_key->commitment_hash = NULL;
    NEW_MP_INT_SIZE(joint_key->commitment_hash, 256, NULL, DYNAMIC_TYPE_BIGINT);
    INIT_MP_INT_SIZE(joint_key->commitment_hash, 256);

    DECL_MP_INT_SIZE(jointkey, 3072);
    NEW_MP_INT_SIZE(jointkey, 3072, NULL, DYNAMIC_TYPE_BIGINT);
    INIT_MP_INT_SIZE(jointkey, 3072);
    DECL_MP_INT_SIZE(commitment, 256);
    NEW_MP_INT_SIZE(commitment, 256, NULL, DYNAMIC_TYPE_BIGINT);
    INIT_MP_INT_SIZE(commitment, 256);

    elgamal_combine_public_keys(guardian, pubkey_map, count, jointkey);
    hash_keys(guardian, pubkey_map, count, commitment);

    ESP_LOGI("COMBINE_ELECTION_PUBLIC_KEYS", "Joint Key: ");
    sp_copy(jointkey, joint_key->joint_key);
    print_sp_int(joint_key->joint_key);

    ESP_LOGI("COMBINE_ELECTION_PUBLIC_KEYS", "Commitment: ");
    sp_copy(commitment, joint_key->commitment_hash);
    print_sp_int(joint_key->commitment_hash);
    FREE_MP_INT_SIZE(jointkey, NULL, DYNAMIC_TYPE_BIGINT);
    FREE_MP_INT_SIZE(commitment, NULL, DYNAMIC_TYPE_BIGINT);
    return 0;
}

int compute_decryption_share(ElectionKeyPair *guardian, CiphertextTally *ciphertally, DecryptionShare *share) {
    //share->object_id = NULL;
    share->object_id = strdup(ciphertally->object_id);

    memcpy(share->guardian_id, guardian->guardian_id, sizeof(guardian->guardian_id));

    share->public_key = NULL;
    NEW_MP_INT_SIZE(share->public_key, 3072, NULL, DYNAMIC_TYPE_BIGINT);
    INIT_MP_INT_SIZE(share->public_key, 3072);
    sp_copy(guardian->public_key, share->public_key);

    share->num_contest = ciphertally->num_contest;
    share->contests = (CiphertextDecryptionContest*)XMALLOC(ciphertally->num_contest * sizeof(CiphertextDecryptionContest), NULL, DYNAMIC_TYPE_BIGINT);
    for (int i = 0; i < ciphertally->num_contest; i++) {
        compute_decryption_share_for_contest(guardian, &ciphertally->contests[i], ciphertally->base_hash , &share->contests[i]);
    }

    return 0;
}

void test_hash() {
    DECL_MP_INT_SIZE(h1, 256);
    NEW_MP_INT_SIZE(h1, 256, NULL, DYNAMIC_TYPE_BIGINT);
    INIT_MP_INT_SIZE(h1, 256);

    DECL_MP_INT_SIZE(h2, 3072);
    NEW_MP_INT_SIZE(h2, 3072, NULL, DYNAMIC_TYPE_BIGINT);
    INIT_MP_INT_SIZE(h2, 3072);

    DECL_MP_INT_SIZE(result, 256);
    NEW_MP_INT_SIZE(result, 256, NULL, DYNAMIC_TYPE_BIGINT);
    INIT_MP_INT_SIZE(result, 256);

    sp_read_radix(h1, "89E73D120610EDBB0004135B2A30430D6C4CDA9B14B13540BEEC915754C5850E", 16);
    sp_read_radix(h2, "8EE4384495F0F3822B87AA1CFA04065C5131DFAE8E24E64647478437521F2D2DFB3BF59269D7771CA19141D7BC4208B2C4D9036E4E23C340BB2F1974ED1D429B10B28BE3E520379AB1EBFCF49A7593CB7E54D16F6B84819395DD57B4DB1A30F243FB22BD8B6B7E206DFCED5D35C11626AF2FB42B1953461565A2B6E0D28B5040DCFB92A382C3B0B228919EEB75DDA182591DBD3A24AA5D2FDB9111C0B2C019F806973455D1E7F755391B520255EBF02AE664C0B61F9688FEDA638B34C163D6A4260FAE66042511F6722F589545EA0B82E4D649B49D2179EC537E901D9B7B2409519D1D5F5BE9C0D37B93242F613F113DE6740CBFA05ACDBAAC5596CBBD0BAB2191F3E5CE389F0E26A37956A00ABE5C643EAA6C2406BBEB8E7806EE89D704DC319A0340E1FB9FD6A8C176D314D8EFC6558E522E6B58C12B55169CA63C42BA9A98C4E830B61F8A1DF03B3EAC39BE5FBBDEC3C92F16C48369300FED6C18F16F283562982DA0FA7D28290A183DF5E80CAE8A4FE48561CD2262D95D6EEE65B8F50C2B", 16);
    //sp_read_radix(h3, "AD9F8B47390107FFFAA6E967224A11EEABE25FE6AEF2AB848B8A9E7474128F93EDDB16A62055BED03430DEBB5769ACAEFDFA3200112E9E83AC332F575B409254A41A4710627A5B74ADA11D9FCA0CB4A628F062010A116F5DE3CF07262D7D2CA625CB44EE195CC4EE9091FEFB827D1F9913141E1ECA08014C91D7AA87B9C79782C9826D2B7B1A79AC6ECE72249A3982ECC564841B9B46CE77E4BB19190E80150B32761576D37795EC46978AD470AA023F9F18EBA3A515E9E27404364EA5FCA722297F273CA92D035EC69157B372B3A5B7E8BAFF23DCAFB9416484418BA2EC54EC72331D5707CF0E219733EF82C142FEAF54774F1A3AE0601AACD2259BA6049504BF4887D2D922A64AB2EBF2D834F3EBB087406254B9ABB28731B81F33CD6BA3CB51332061F87723A49E2F181F570A20C0D6EF95C77A86DEFFBC86C2A5D867143BB6CE0F4547E8E96EEE47865AFF918ADD962BF93D0F3EB0DA6C4AACE1A45292B64CB196B64FF84A748580C67B4EC593AF902A79424F826BFF4F594DFA6776E191", 16);
    //sp_read_radix(h4, "F2B15DB15EEB95C1FD7204DCE7C35F713A2494658277E79039D946D647B917D6EF42B3DAD0D824DCCD743729AA8E3212070A65BA8D0791E8C49578AE14C7672980B21D713050B4C0ABE008482BC31573129B2BE7D21FA373830EA297223E487F044071973392650E8D643E7A702634D1F0497B1BD63274DF5BC3E0179DDD683EFFE0450D1AEE9C1324BC5157C4A6140C905F3F85F2BD3E1DAFC63C337585F9DB955AA30D98C71B84A843567EAE9601B908A40034F5EC0FB4FBD7DE679BBCA5983C863D7BBD29EBB6FC87D847B6B84A584F4FBCB3A523F3970F79E03A89373778A9DA170B12BD7BF0027DD752C66167AA763CD2E961ADC3354DF09CE531FFC0F97491C4392C68D647E77FE91C0CEF7B141DBD600AB54B056705905D13D723E68440EF21CD9A0BBA4FDA9C51C071266E79537AD3DEBAFC2C725254251F7D2176825C4447E6CD61D4619077DC0460F10E7B8AB66CC9ADE1BAD2238EA50F01E085EFE407B0EBB360A50807963C98392EA6BDC2A1E37BD656A0936543357CB299A6D0", 16);
    //sp_read_radix(h5, "54705874684D4286B2330509C91D1036EE92222FAB7E613554BB76ACF70B8B53F273FE2F8282BEA79E42D1212863EADB4236B98521C1A4657E07239541E6855785C7DA958AFD8B64E4ACC9E79803FAFC3115357593A37764B2B2D0B049454FF2ED0E33AB57F9A79DD9031110FA554B6827DC0F6FE0A99A85B3E690218B2B69128852EFECA7BF159AF58C863EA83E0574E9DF4957BBF6FFC83F2DD76F0168D56AA3E590091418D6D5FCAA611C1E9EB4BEBF41C983BDC379742E91CA07F74C5240E905BBAE11C50AAEF4B4028083A76C9B9F5509E55B8063528ED8BB7265F1071D4345B6AB5E5B5862E1270122E53F9BB7BD8B77902EABCB7659D53B604F82043694A5C0D146947A88CCA467AADB5709E3C6B84B655DC02BDE35DC83EF3138CBA034FD1911A26326489386CB65B66A53F7493FD1DB4786DAE2F1E3ED0F4A962B4E698A946F08553B1B67441F8AF6FAD1C03D0FAE56293E009594B6A231B895CFD5B5FB0C8153A264A2B4658D895D795B12ED4FFDE97CF02E4DB9C01171DA787281", 16);
    //sp_read_radix(h6, "EA08C4079374BFEE2267D2DA5C5E12D9C28112BE3C03EC8667C7950A3BAE1217625F9BBE88DFFC495D27246755732392AE491293EC26D47E1FCD71F51C2EA183554B070345EE82BC942DBA5429E345FEC8B8862A776EF88BB6A96F338CFA7C1020A45527466EA91558FA130FD6BA7093AC751AD6E7325504B067E713E0764E22F3068DAC6E35D3ED9CA4885CCE72EA2AAB24D4BCA92279757DCBF38E05F12BEDA085AB9D842C14EE2F85BAE9ED654497C788ABA982E2D010A0986E01B62BBB35A7DB5AD8338E12D916545393599C12ACDC8B54063D9F128E32C14BD6FF7CA272B2E8B43CA8D29412D821C5B30975225C49DA7D5F94724F0CE75CD68995FBEBC2033FB1C9BEBD543CF33EF440B46A3096B43C4AD3EBA9D13A269FD65158467E65762AE4A42AE8FCABB2A417C87158B27072551DA0C5DC20D00AF3092BF81C522B07F3E78190564DC0E0965FD14B09C4D26ADA51DF951063D5A60AACF10F9229CD5CF990DE31DE1808A5DAD6F67043F98A14446AE0B2E38A8E96FC9AAE6CD0FF86", 16);
    //hash_challenge(h1, h2, h3, h4, h5, h6, result);
    hash(h1, h2, result);
    print_sp_int(result);
    //nonces(seed, result);
}