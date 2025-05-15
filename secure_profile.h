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
    unsigned char* gmac;
    size_t gmac_len;
    time_t generation_timestamp;
    char* password;
} SecureProfile;

SecureProfile* create_SecureProfile(const char* name, const char* password, int id);
int generate_entity_keys(SecureProfile* entity);
int generate_rsa_keys(SecureProfile* entity);
int save_ec_keys_to_files(SecureProfile* entity, EVP_PKEY* temp_key);
int save_rsa_keys_to_files(SecureProfile* entity, EVP_PKEY* temp_rsa_key);