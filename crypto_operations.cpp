#pragma warning(disable:4996) 

#include "crypto_operations.h"
#include "gmac_operations.h"

int get_sym_elements_id_for_transaction(int entity1_id, int entity2_id)
{
    int id1 = (entity1_id < entity2_id) ? entity1_id : entity2_id;
    int id2 = (entity1_id < entity2_id) ? entity2_id : entity1_id;

    // verifica daca ULTIMUL sym creat este intre aceleasi entitati
    if (last_entity1 == id1 && last_entity2 == id2 && global_sym_counter > 0)
    {
        // daca da, returnam acelasi ID
        return global_sym_counter;
    }
    else {
        // daca nu, returnam -1 pentru a indica că nu există handshake
        return -1;
    }
}

int create_new_sym_elements(int entity1_id, int entity2_id)
{
    int id1 = (entity1_id < entity2_id) ? entity1_id : entity2_id;
    int id2 = (entity1_id < entity2_id) ? entity2_id : entity1_id;

    global_sym_counter++;
    last_entity1 = id1;
    last_entity2 = id2;

    return global_sym_counter;
}

int read_keys(const char* privateKeyFilename, const char* pubKeyFilename, const char* password, EVP_PKEY** pkey, EVP_PKEY** peerkey)
{
    *pkey = EVP_PKEY_new();
    *peerkey = EVP_PKEY_new();

    FILE* fp = fopen(privateKeyFilename, "r");
    if (fp == NULL) {
        fprintf(stderr, "Null Pointer for %s file\n", privateKeyFilename);
        EVP_PKEY_free(*pkey);
        EVP_PKEY_free(*peerkey);
        *pkey = NULL;
        *peerkey = NULL;
        return 0;
    }

    // Folosește parola specifică
    if (!PEM_read_PrivateKey(fp, pkey, NULL, (void*)password)) {
        fprintf(stderr, "Failed to read private key from %s\n", privateKeyFilename);
        fclose(fp);
        EVP_PKEY_free(*pkey);
        EVP_PKEY_free(*peerkey);
        *pkey = NULL;
        *peerkey = NULL;
        return 0;
    }
    fclose(fp);

    FILE* fpp = fopen(pubKeyFilename, "r");
    if (fpp == NULL) {
        fprintf(stderr, "Null Pointer for %s file\n", pubKeyFilename);
        EVP_PKEY_free(*pkey);
        EVP_PKEY_free(*peerkey);
        *pkey = NULL;
        *peerkey = NULL;
        return 0;
    }
    if (!PEM_read_PUBKEY(fpp, peerkey, NULL, NULL)) {
        fprintf(stderr, "Failed to read public key from %s\n", pubKeyFilename);
        fclose(fpp);
        EVP_PKEY_free(*pkey);
        EVP_PKEY_free(*peerkey);
        *pkey = NULL;
        *peerkey = NULL;
        return 0;
    }
    fclose(fpp);

    return 1;
}

int generate_shared_secret(EVP_PKEY* pkey, EVP_PKEY* peerkey, unsigned char** skey, size_t* skeylen)
{
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(pkey, NULL);
    if (!ctx) {
        fprintf(stderr, "Failed to create ECDH context\n");
        return 0;
    }

    if (EVP_PKEY_derive_init(ctx) <= 0) {
        fprintf(stderr, "Context Error Occurs\n");
        EVP_PKEY_CTX_free(ctx);
        return 0;
    }

    if (EVP_PKEY_derive_set_peer(ctx, peerkey) <= 0) {
        fprintf(stderr, "ECDH internal error\n");
        EVP_PKEY_CTX_free(ctx);
        return 0;
    }

    if (EVP_PKEY_derive(ctx, NULL, skeylen) <= 0) {
        fprintf(stderr, "Fail to generate length for shared key\n");
        EVP_PKEY_CTX_free(ctx);
        return 0;
    }

    *skey = (unsigned char*)OPENSSL_malloc(*skeylen);
    if (!*skey) {
        fprintf(stderr, "Failed to allocate memory for shared key\n");
        EVP_PKEY_CTX_free(ctx);
        return 0;
    }

    if (EVP_PKEY_derive(ctx, *skey, skeylen) <= 0) {
        fprintf(stderr, "Fail to generate shared key\n");
        OPENSSL_free(*skey);
        *skey = NULL;
        EVP_PKEY_CTX_free(ctx);
        return 0;
    }

    EVP_PKEY_CTX_free(ctx);
    return 1;
}

int extract_coordinates(EVP_PKEY* pkey, EVP_PKEY* peerkey, unsigned char** x_bytes, size_t* x_len, unsigned char** y_bytes, size_t* y_len)
{
    const EC_KEY* ec_key = EVP_PKEY_get0_EC_KEY(pkey);
    if (!ec_key) {
        fprintf(stderr, "Failed to get EC_KEY from private key\n");
        return 0;
    }

    const EC_KEY* peer_ec_key = EVP_PKEY_get0_EC_KEY(peerkey);
    if (!peer_ec_key) {
        fprintf(stderr, "Failed to get EC_KEY from peer key\n");
        return 0;
    }

    const EC_GROUP* group = EC_KEY_get0_group(ec_key);
    if (!group) {
        fprintf(stderr, "Failed to get EC group\n");
        return 0;
    }

    const EC_POINT* peer_point = EC_KEY_get0_public_key(peer_ec_key);
    if (!peer_point) {
        fprintf(stderr, "Failed to get public key point from peer key\n");
        return 0;
    }

    const BIGNUM* priv_key = EC_KEY_get0_private_key(ec_key);
    if (!priv_key) {
        fprintf(stderr, "Failed to get private key scalar\n");
        return 0;
    }

    EC_POINT* point = EC_POINT_new(group);
    if (!point) {
        fprintf(stderr, "Failed to create EC point\n");
        return 0;
    }

    // shared_point = priv_key * peer_point
    if (!EC_POINT_mul(group, point, NULL, peer_point, priv_key, NULL)) {
        fprintf(stderr, "Failed to compute ECDH shared point\n");
        EC_POINT_free(point);
        return 0;
    }

    BIGNUM* x = BN_new();
    BIGNUM* y = BN_new();
    if (!x || !y) {
        fprintf(stderr, "Failed to allocate BIGNUMs for coordinates\n");
        if (x) BN_free(x);
        if (y) BN_free(y);
        EC_POINT_free(point);
        return 0;
    }

    if (!EC_POINT_get_affine_coordinates_GFp(group, point, x, y, NULL)) {
        fprintf(stderr, "Failed to get affine coordinates\n");
        BN_free(x);
        BN_free(y);
        EC_POINT_free(point);
        return 0;
    }

    *x_len = BN_num_bytes(x);
    *y_len = BN_num_bytes(y);
    *x_bytes = (unsigned char*)malloc(*x_len);
    *y_bytes = (unsigned char*)malloc(*y_len);
    if (!*x_bytes || !*y_bytes) {
        fprintf(stderr, "Failed to allocate memory for coordinates\n");
        if (*x_bytes) free(*x_bytes);
        if (*y_bytes) free(*y_bytes);
        BN_free(x);
        BN_free(y);
        EC_POINT_free(point);
        return 0;
    }

    BN_bn2bin(x, *x_bytes);
    BN_bn2bin(y, *y_bytes);

    BN_free(x);
    BN_free(y);
    EC_POINT_free(point);
    return 1;
}

int derive_symmetric_key(unsigned char* x_bytes, size_t x_len, unsigned char* y_bytes, size_t y_len, unsigned char** symKey, unsigned char** symRightUnused, size_t* symRightUnusedLen)
{
    unsigned char sha256_hash[SHA256_DIGEST_LENGTH];
    SHA256(x_bytes, x_len, sha256_hash);

    unsigned char first_half[16], second_half[16];
    memcpy(first_half, sha256_hash, 16);
    memcpy(second_half, sha256_hash + 16, 16);

    unsigned char* symLeft = (unsigned char*)malloc(16);
    if (!symLeft) {
        fprintf(stderr, "Failed to allocate memory for SymLeft\n");
        return 0;
    }
    for (int i = 0; i < 16; i++) {
        symLeft[i] = first_half[i] ^ second_half[i];
    }

    // y: PBKDF2 cu SHA-384 fara salt
    size_t symRightLen = 48;
    unsigned char* symRight = (unsigned char*)malloc(symRightLen);
    if (!symRight) {
        fprintf(stderr, "Failed to allocate memory for SymRight\n");
        free(symLeft);
        return 0;
    }

    if (PKCS5_PBKDF2_HMAC((const char*)y_bytes, y_len, NULL, 0, 1000, EVP_sha384(), symRightLen, symRight) <= 0) {
        fprintf(stderr, "Failed to derive SymRight with PBKDF2\n");
        free(symLeft);
        free(symRight);
        return 0;
    }

    // symKey: XOR intre SymLeft si primii 16 octeți din SymRight
    *symKey = (unsigned char*)malloc(32);
    if (!*symKey) {
        fprintf(stderr, "Failed to allocate memory for SymKey\n");
        free(symLeft);
        free(symRight);
        return 0;
    }
    for (int i = 0; i < 16; i++) {
        (*symKey)[i] = symLeft[i] ^ symRight[i];
    }

    // octetii neutilizati din symRight
    *symRightUnusedLen = symRightLen - 16;
    *symRightUnused = (unsigned char*)malloc(*symRightUnusedLen);
    if (!*symRightUnused) {
        fprintf(stderr, "Failed to allocate memory for SymRight unused bytes\n");
        free(symLeft);
        free(symRight);
        free(*symKey);
        *symKey = NULL;
        return 0;
    }
    memcpy(*symRightUnused, symRight + 16, *symRightUnusedLen);

    free(symLeft);
    free(symRight);
    return 1;
}

unsigned char* ecdh(const char* ecPrivateKeyFilename, const char* ecPubKeyFilename, const char* password1, const char* password2, unsigned char** symRightUnused, size_t* symRightUnusedLen, unsigned char** iv) {
    EVP_PKEY* pkey = NULL;
    EVP_PKEY* peerkey = NULL;
    unsigned char* x_bytes = NULL;
    size_t x_len;
    unsigned char* y_bytes = NULL;
    size_t y_len;
    unsigned char* symKey = NULL;

    if (!read_keys(ecPrivateKeyFilename, ecPubKeyFilename, password1, &pkey, &peerkey)) {
        return NULL;
    }

    // x si y
    if (!extract_coordinates(pkey, peerkey, &x_bytes, &x_len, &y_bytes, &y_len)) {
        EVP_PKEY_free(pkey);
        EVP_PKEY_free(peerkey);
        return NULL;
    }

    if (!derive_symmetric_key(x_bytes, x_len, y_bytes, y_len, &symKey, symRightUnused, symRightUnusedLen)) {
        free(x_bytes);
        free(y_bytes);
        EVP_PKEY_free(pkey);
        EVP_PKEY_free(peerkey);
        return NULL;
    }

    free(x_bytes);
    free(y_bytes);
    EVP_PKEY_free(pkey);
    EVP_PKEY_free(peerkey);

    *iv = (unsigned char*)malloc(16);
    memcpy(*iv, *symRightUnused, 16);

    return symKey;
}

int generate_handshake(SecureProfile* entity1, SecureProfile* entity2)
{
    char private_path_1[256], public_path_1[256];
    char private_path_2[256], public_path_2[256];
    unsigned char* symRightUnused1 = NULL;
    size_t symRightUnusedLength1 = 0;
    unsigned char* symRightUnused2 = NULL;
    size_t symRightUnusedLength2 = 0;
    unsigned char* symKey1 = NULL;
    unsigned char* symKey2 = NULL;
    unsigned char* iv1 = NULL;
    unsigned char* iv2 = NULL;

    char log_msg[256];
    snprintf(log_msg, sizeof(log_msg), "Initiating handshake with %s", entity2->entity_name);
    log_action(entity1->entity_name, log_msg);

    snprintf(private_path_1, sizeof(private_path_1), "keys/%d_priv.ecc", entity1->entity_id);
    snprintf(public_path_1, sizeof(public_path_1), "keys/%d_pub.ecc", entity1->entity_id);
    snprintf(private_path_2, sizeof(private_path_2), "keys/%d_priv.ecc", entity2->entity_id);
    snprintf(public_path_2, sizeof(public_path_2), "keys/%d_pub.ecc", entity2->entity_id);

    //autenticitatea cheilor publice
    printf("Verifying authenticity of %s's public key...\n", entity2->entity_name);
    if (!validate_autenticity(entity2))
    {
        fprintf(stderr, "Failed to validate authenticity of %s's public key\n", entity2->entity_name);
        snprintf(log_msg, sizeof(log_msg), "Failed to validate authenticity of %s", entity2->entity_name);
        log_action(entity1->entity_name, log_msg);
        return 0;
    }

    printf("Verifying authenticity of %s's public key...\n", entity1->entity_name);
    if (!validate_autenticity(entity1))
    {
        fprintf(stderr, "Failed to validate authenticity of %s's public key\n", entity1->entity_name);
        snprintf(log_msg, sizeof(log_msg), "Failed to validate authenticity of %s", entity1->entity_name);
        log_action(entity2->entity_name, log_msg);
        return 0;
    }

    // schimb de chei ECDH - entity1
    printf("%s switches keys with %s...\n", entity1->entity_name, entity2->entity_name);
    symKey1 = ecdh(private_path_1, public_path_2, entity1->password, NULL, &symRightUnused1, &symRightUnusedLength1, &iv1);

    if (!symKey1)
    {
        fprintf(stderr, "ECDH failed for %s\n", entity1->entity_name);
        return 0;
    }
    snprintf(log_msg, sizeof(log_msg), "Performed ECDH key exchange with %s", entity2->entity_name);
    log_action(entity1->entity_name, log_msg);

    // schimb de chei ECDH - entity2
    printf("%s switches keys with %s...\n", entity2->entity_name, entity1->entity_name);
    symKey2 = ecdh(private_path_2, public_path_1, entity2->password, NULL, &symRightUnused2, &symRightUnusedLength2, &iv2);

    if (!symKey2)
    {
        fprintf(stderr, "ECDH failed for %s\n", entity2->entity_name);
        if (iv1) free(iv1);
        if (symRightUnused1) free(symRightUnused1);
        if (symKey1) free(symKey1);
        return 0;
    }

    if (!symKey1 || !symKey2 || memcmp(symKey1, symKey2, 16) != 0) {
        fprintf(stderr, "Handshake failed: symmetric keys do not match!\n");
        if (iv2) free(iv2);
        if (symRightUnused2) free(symRightUnused2);
        if (symKey2) free(symKey2);
        if (iv1) free(iv1);
        if (symRightUnused1) free(symRightUnused1);
        if (symKey1) free(symKey1);
        return 0;
    }

    printf("Handshake successful! Saving symmetric elements...\n");

    int sym_elements_id = create_new_sym_elements(entity1->entity_id, entity2->entity_id);

    if (!save_sym_elements(symKey1, iv1, sym_elements_id)) {
        fprintf(stderr, "Failed to save SymElements\n");
        if (iv2) free(iv2);
        if (symRightUnused2) free(symRightUnused2);
        if (symKey2) free(symKey2);
        if (iv1) free(iv1);
        if (symRightUnused1) free(symRightUnused1);
        if (symKey1) free(symKey1);
        return 0;
    }
    else
    {
        printf("SymElements saved with ID: %d for entities %d and %d\n",
            sym_elements_id, entity1->entity_id, entity2->entity_id);
        snprintf(log_msg, sizeof(log_msg), "Saved symmetric elements for communication with %s (ID: %d)",
            entity2->entity_name, sym_elements_id);
        log_action(entity1->entity_name, log_msg);
    }

    printf("Symmetric elements saved with ID: %d\n", sym_elements_id);
    printf("Handshake completed successfully between %s (ID: %d) and %s (ID: %d)\n",
        entity1->entity_name, entity1->entity_id,
        entity2->entity_name, entity2->entity_id);

    snprintf(log_msg, sizeof(log_msg), "Completed handshake with %s", entity2->entity_name);
    log_action(entity1->entity_name, log_msg);

    if (iv2) free(iv2);
    if (symRightUnused2) free(symRightUnused2);
    if (symKey2) free(symKey2);
    if (iv1) free(iv1);
    if (symRightUnused1) free(symRightUnused1);
    if (symKey1) free(symKey1);

    return 1;
}

int aes_128_fancy_ofb_encrypt(unsigned char* plaintext, size_t plaintext_len, unsigned char* key, unsigned char* iv, unsigned char** ciphertext, size_t* ciphertext_len) {
    AES_KEY aes_key;
    unsigned char* output = NULL;

    // verifica lungimea cheii
    if (AES_set_encrypt_key(key, 128, &aes_key) != 0) {
        fprintf(stderr, "Error setting AES key!\n");
        return 0;
    }

    // inverseaza IV-ul
    unsigned char inv_iv[AES_BLOCK_SIZE];
    for (int i = 0; i < AES_BLOCK_SIZE; i++) {
        inv_iv[i] = iv[AES_BLOCK_SIZE - 1 - i];
    }

    output = (unsigned char*)malloc(plaintext_len);
    if (!output) {
        fprintf(stderr, "Failed to allocate memory for ciphertext\n");
        return 0;
    }

    unsigned char current_iv[AES_BLOCK_SIZE];
    memcpy(current_iv, iv, AES_BLOCK_SIZE);

    for (size_t i = 0; i < plaintext_len; i += AES_BLOCK_SIZE) 
    {
        unsigned char encrypted_block[AES_BLOCK_SIZE];
        unsigned char modified_block[AES_BLOCK_SIZE];

        AES_encrypt(current_iv, encrypted_block, &aes_key);

        memcpy(current_iv, encrypted_block, AES_BLOCK_SIZE);

        // XOR cu inv_IV
        for (int j = 0; j < AES_BLOCK_SIZE; j++) 
        {
            modified_block[j] = encrypted_block[j] ^ inv_iv[j];
        }

        size_t block_len = (plaintext_len - i < AES_BLOCK_SIZE) ?
            (plaintext_len - i) : AES_BLOCK_SIZE;

        for (size_t j = 0; j < block_len; j++) {
            output[i + j] = modified_block[j] ^ plaintext[i + j];
        }
    }

    *ciphertext = output;
    *ciphertext_len = plaintext_len;

    return 1;
}

int aes_128_fancy_ofb_decrypt(unsigned char* ciphertext, size_t ciphertext_len, unsigned char* key, unsigned char* iv, unsigned char** plaintext, size_t* plaintext_len)
{
    AES_KEY aes_key;
    unsigned char* output = NULL;

    // verifica lungimea cheii
    if (AES_set_encrypt_key(key, 128, &aes_key) != 0) {
        fprintf(stderr, "Error setting AES key!\n");
        return 0;
    }

    // inverseaza IV-ul
    unsigned char inv_iv[AES_BLOCK_SIZE];
    for (int i = 0; i < AES_BLOCK_SIZE; i++) {
        inv_iv[i] = iv[AES_BLOCK_SIZE - 1 - i];
    }

    output = (unsigned char*)malloc(ciphertext_len);
    if (!output) {
        fprintf(stderr, "Failed to allocate memory for plaintext\n");
        return 0;
    }

    unsigned char current_iv[AES_BLOCK_SIZE];
    memcpy(current_iv, iv, AES_BLOCK_SIZE);

    for (size_t i = 0; i < ciphertext_len; i += AES_BLOCK_SIZE) 
    {
        unsigned char encrypted_block[AES_BLOCK_SIZE];
        unsigned char modified_block[AES_BLOCK_SIZE];

        AES_encrypt(current_iv, encrypted_block, &aes_key);

        memcpy(current_iv, encrypted_block, AES_BLOCK_SIZE);

        // XOR cu inv_IV
        for (int j = 0; j < AES_BLOCK_SIZE; j++) {
            modified_block[j] = encrypted_block[j] ^ inv_iv[j];
        }

        size_t block_len = (ciphertext_len - i < AES_BLOCK_SIZE) ?
            (ciphertext_len - i) : AES_BLOCK_SIZE;

        for (size_t j = 0; j < block_len; j++) {
            output[i + j] = modified_block[j] ^ ciphertext[i + j];
        }
    }

    *plaintext = output;
    *plaintext_len = ciphertext_len;

    return 1;
}
