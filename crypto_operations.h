#pragma once

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/ecdh.h>
#include <openssl/aes.h>
#include <openssl/sha.h>
#include "secure_profile.h"
#include "file_operations.h"
#include "logging.h"

static int global_sym_counter = 0;
static int last_entity1 = -1;
static int last_entity2 = -1;

int read_keys(const char* privateKeyFilename, const char* pubKeyFilename, const char* password, EVP_PKEY** pkey, EVP_PKEY** peerkey);
int generate_shared_secret(EVP_PKEY* pkey, EVP_PKEY* peerkey, unsigned char** skey, size_t* skeylen);
int extract_coordinates(EVP_PKEY* pkey, EVP_PKEY* peerkey, unsigned char** x_bytes, size_t* x_len, unsigned char** y_bytes, size_t* y_len);
int derive_symmetric_key(unsigned char* x_bytes, size_t x_len, unsigned char* y_bytes, size_t y_len, unsigned char** symKey, unsigned char** symRightUnused, size_t* symRightUnusedLen);
unsigned char* ecdh(const char* ecPrivateKeyFilename, const char* ecPubKeyFilename, const char* password1, const char* password2, unsigned char** symRightUnused, size_t* symRightUnusedLen, unsigned char** iv);
int generate_handshake(SecureProfile* entity1, SecureProfile* entity2,
    const char* password1, const char* password2); 
int aes_128_fancy_ofb_encrypt(unsigned char* plaintext, size_t plaintext_len, unsigned char* key, unsigned char* iv, unsigned char** ciphertext, size_t* ciphertext_len);
int aes_128_fancy_ofb_decrypt(unsigned char* ciphertext, size_t ciphertext_len, unsigned char* key, unsigned char* iv, unsigned char** plaintext, size_t* plaintext_len);
int get_sym_elements_id_for_transaction(int entity1_id, int entity2_id);
int create_new_sym_elements(int entity1_id, int entity2_id);
