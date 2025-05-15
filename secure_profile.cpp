#pragma warning(disable:4996)

#include "secure_profile.h"

SecureProfile* create_SecureProfile(const char* name, const char* password, int id) 
{
    SecureProfile* entity = (SecureProfile*)malloc(sizeof(SecureProfile));
    if (!entity) return NULL;

    entity->entity_name = strdup(name);
    entity->entity_id = id;
    entity->gmac = NULL;
    entity->gmac_len = 0;

    if (password) {
        entity->password = strdup(password);
    }
    else {
        entity->password = NULL;
    }

    time_t base_time = 1115240705;
    entity->generation_timestamp = base_time + 1000;

    return entity;
}

int generate_entity_keys(SecureProfile* entity)
{
    EVP_PKEY_CTX* ctx = NULL;
    EVP_PKEY* temp_key = NULL;
    int ret = 0;

    ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
    if (!ctx) {
        fprintf(stderr, "Failed to create context\n");
        goto cleanup;
    }

    if (EVP_PKEY_keygen_init(ctx) <= 0) {
        fprintf(stderr, "Failed to initialize context\n");
        goto cleanup;
    }

    if (EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx, NID_X9_62_prime256v1) <= 0) {
        fprintf(stderr, "Failed to set curve secp256r1\n");
        goto cleanup;
    }

    if (EVP_PKEY_keygen(ctx, &temp_key) <= 0) {
        fprintf(stderr, "Failed to generate key\n");
        log_action(entity->entity_name, "Failed to generate EC key pair");
        goto cleanup;
    }

    printf("Generated key with curve NID_X9_62_prime256v1\n");
    log_action(entity->entity_name, "Generated EC key pair successfully");

    if (!save_ec_keys_to_files(entity, temp_key)) {
        fprintf(stderr, "Failed to save EC keys\n");
        goto cleanup;
    }

    ret = 1;

cleanup:
    if (temp_key) EVP_PKEY_free(temp_key);
    if (ctx) EVP_PKEY_CTX_free(ctx);
    return ret;
}

int generate_rsa_keys(SecureProfile* entity) {
    EVP_PKEY_CTX* ctx = NULL;
    EVP_PKEY* temp_rsa_key = NULL;
    int ret = 0;

    ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    if (!ctx) {
        fprintf(stderr, "Failed to create RSA context\n");
        goto cleanup;
    }

    if (EVP_PKEY_keygen_init(ctx) <= 0) {
        fprintf(stderr, "Failed to initialize RSA context\n");
        goto cleanup;
    }

    if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 3072) <= 0) {
        fprintf(stderr, "Failed to set RSA key size\n");
        goto cleanup;
    }

    if (EVP_PKEY_keygen(ctx, &temp_rsa_key) <= 0) {
        fprintf(stderr, "Failed to generate RSA key\n");
        goto cleanup;
    }

    log_action(entity->entity_name, "Generated RSA 3072-bit key pair");

    if (!save_rsa_keys_to_files(entity, temp_rsa_key)) {
        fprintf(stderr, "Failed to save RSA keys\n");
        goto cleanup;
    }

    ret = 1;

cleanup:
    if (temp_rsa_key) EVP_PKEY_free(temp_rsa_key);
    if (ctx) EVP_PKEY_CTX_free(ctx);
    return ret;
}

int save_ec_keys_to_files(SecureProfile* entity, EVP_PKEY* temp_key) {
    BIO* private_bio = NULL;
    BIO* public_bio = NULL;
    char private_path[256], public_path[256];
    int ret = 0;

    create_output_dirs();

    snprintf(private_path, sizeof(private_path), "keys/%d_priv.ecc", entity->entity_id);
    snprintf(public_path, sizeof(public_path), "keys/%d_pub.ecc", entity->entity_id);

    private_bio = BIO_new_file(private_path, "w");
    public_bio = BIO_new_file(public_path, "w");

    if (!private_bio || !public_bio) {
        fprintf(stderr, "Failed to open BIO files\n");
        goto cleanup;
    }

    if (!PEM_write_bio_PrivateKey(private_bio, temp_key, EVP_aes_256_cbc(),
        (unsigned char*)entity->password, strlen(entity->password), NULL, NULL)) {
        fprintf(stderr, "Failed to save private key\n");
        log_action(entity->entity_name, "Failed to save private key");
        goto cleanup;
    }

    if (!PEM_write_bio_PUBKEY(public_bio, temp_key)) {
        fprintf(stderr, "Failed to save public key!\n");
        log_action(entity->entity_name, "Failed to save public key");
        goto cleanup;
    }

    log_action(entity->entity_name, "Saved EC key pair to PEM files");
    ret = 1;

cleanup:
    if (private_bio) BIO_free(private_bio);
    if (public_bio) BIO_free(public_bio);
    return ret;
}

int save_rsa_keys_to_files(SecureProfile* entity, EVP_PKEY* temp_rsa_key) {
    BIO* private_bio = NULL;
    BIO* public_bio = NULL;
    char private_path[256], public_path[256];
    RSA* rsa = NULL;
    int ret = 0;

    snprintf(private_path, sizeof(private_path), "keys/%d_priv.rsa", entity->entity_id);
    snprintf(public_path, sizeof(public_path), "keys/%d_pub.rsa", entity->entity_id);

    private_bio = BIO_new_file(private_path, "w");
    public_bio = BIO_new_file(public_path, "w");

    if (!private_bio || !public_bio) {
        fprintf(stderr, "Failed to open BIO files for RSA keys\n");
        if (private_bio) BIO_free(private_bio);
        if (public_bio) BIO_free(public_bio);
        return 0;
    }

    rsa = EVP_PKEY_get1_RSA(temp_rsa_key);
    if (!rsa) {
        fprintf(stderr, "Failed to extract RSA key\n");
        BIO_free(private_bio);
        BIO_free(public_bio);
        return 0;
    }

    if (!PEM_write_bio_RSAPrivateKey(private_bio, rsa, EVP_aes_256_cbc(),
        (unsigned char*)entity->password, strlen(entity->password), NULL, NULL)) {
        fprintf(stderr, "Failed to save RSA private key\n");
        log_action(entity->entity_name, "Failed to save RSA private key");
        RSA_free(rsa);
        BIO_free(private_bio);
        BIO_free(public_bio);
        return 0;
    }

    if (!PEM_write_bio_RSA_PUBKEY(public_bio, rsa)) {
        fprintf(stderr, "Failed to save RSA public key\n");
        log_action(entity->entity_name, "Failed to save RSA public key");
        RSA_free(rsa);
        BIO_free(private_bio);
        BIO_free(public_bio);
        return 0;
    }

    RSA_free(rsa);
    BIO_free(private_bio);
    BIO_free(public_bio);

    log_action(entity->entity_name, "Saved RSA key pair in PKCS#1 format");

    return 1;
}