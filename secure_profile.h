#pragma once

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/bio.h>
#include <string.h>
#include <time.h>
#include "logging.h"

typedef struct {
    char* entity_name;
    int entity_id;
    EVP_PKEY* private_key;
    EVP_PKEY* public_key;
    EVP_PKEY* rsa_key;
    unsigned char* gmac;
    size_t gmac_len;
    time_t generation_timestamp;
} SecureProfile;


SecureProfile* create_SecureProfile(const char* name, int id);
int generate_entity_keys(SecureProfile* entity);
int generate_rsa_keys(SecureProfile* entity);
int save_entity_keys(SecureProfile* entity);
int save_rsa_keys(SecureProfile* entity);

SecureProfile* create_SecureProfile(const char* name, int id) {
    SecureProfile* entity = (SecureProfile*)malloc(sizeof(SecureProfile));
    if (!entity) return NULL;

    entity->entity_name = strdup(name);
    entity->entity_id = id;
    entity->private_key = NULL;
    entity->public_key = NULL;
    entity->rsa_key = NULL;
    entity->gmac = NULL;
    entity->gmac_len = 0;

    time_t base_time = 1115240705;
    entity->generation_timestamp = base_time + 1000;

    return entity;
}

int generate_entity_keys(SecureProfile* entity) {
    EVP_PKEY_CTX* ctx = NULL;
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

    if (EVP_PKEY_keygen(ctx, &entity->private_key) <= 0) {
        fprintf(stderr, "Failed to generate key\n");
        log_action(entity->entity_name, "Failed to generate EC key pair");
        goto cleanup;
    }

    printf("Generated key with curve NID_X9_62_prime256v1\n");
    log_action(entity->entity_name, "Generated EC key pair successfully");

    ret = 1;
cleanup:
    if (ctx) EVP_PKEY_CTX_free(ctx);
    return ret;
}

int generate_rsa_keys(SecureProfile* entity)
{
    EVP_PKEY_CTX* ctx = NULL;

    ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);

    EVP_PKEY_keygen_init(ctx);

    EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 3072);

    EVP_PKEY_keygen(ctx, &entity->rsa_key);

    log_action(entity->entity_name, "Generated RSA 3072-bit key pair");

    EVP_PKEY_CTX_free(ctx);

    return 1;
}

int save_entity_keys(SecureProfile* entity)
{
    BIO* private_bio = NULL;
    BIO* public_bio = NULL;
    char private_path[256], public_path[256];
    int ret = 0;
    const char* password = "password";

    create_output_dirs();

    snprintf(private_path, sizeof(private_path), "keys/private_%s.pem", entity->entity_name);
    snprintf(public_path, sizeof(public_path), "keys/public_%s.pem", entity->entity_name);

    private_bio = BIO_new_file(private_path, "w");
    public_bio = BIO_new_file(public_path, "w");

    if (!private_bio || !public_bio) {
        fprintf(stderr, "Failed to open BIO files\n");
        goto cleanup;
    }

    if (!PEM_write_bio_PrivateKey(private_bio, entity->private_key, EVP_aes_256_cbc(), (unsigned char*)password, strlen(password), NULL, NULL)) {
        fprintf(stderr, "Failed to save private key\n");
        log_action(entity->entity_name, "Failed to save private key");
        goto cleanup;
    }

    if (!PEM_write_bio_PUBKEY(public_bio, entity->private_key)) {
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

int save_rsa_keys(SecureProfile* entity)
{
    BIO* private_bio = NULL;
    BIO* public_bio = NULL;
    char private_path[256], public_path[256];

    snprintf(private_path, sizeof(private_path), "keys/rsa_private_%s.pem", entity->entity_name);
    snprintf(public_path, sizeof(public_path), "keys/rsa_public_%s.pem", entity->entity_name);

    private_bio = BIO_new_file(private_path, "w");
    public_bio = BIO_new_file(public_path, "w");

    PEM_write_bio_PrivateKey(private_bio, entity->rsa_key, EVP_aes_256_cbc(), (unsigned char*)"password", strlen("password"), NULL, NULL);

    PEM_write_bio_PUBKEY(public_bio, entity->rsa_key);

    BIO_free(private_bio);
    BIO_free(public_bio);

    return 1;
}
