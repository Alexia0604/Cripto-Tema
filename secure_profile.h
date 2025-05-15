#pragma once

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/bio.h>
#include <string.h>
#include <time.h>
#include "logging.h"

typedef struct {
    char* entity_name;
    char* password;
    int entity_id;
    EVP_PKEY* private_key;
    EVP_PKEY* public_key;
    EVP_PKEY* rsa_key;
    unsigned char* gmac;
    size_t gmac_len;
    time_t generation_timestamp;
} SecureProfile;


SecureProfile* create_SecureProfile(const char* name,const char* password, int id);
int generate_entity_keys(SecureProfile* entity);
int generate_rsa_keys(SecureProfile* entity);
int save_entity_keys(SecureProfile* entity);
int save_rsa_keys(SecureProfile* entity);