#pragma once

#include <openssl/evp.h>
#include <openssl/asn1.h>
#include <openssl/asn1t.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include "secure_profile.h"
#include "logging.h"


typedef struct PubKeyMAC {
    ASN1_PRINTABLESTRING* PubKeyName;
    ASN1_OCTET_STRING* MACKey;
    ASN1_OCTET_STRING* MACValue;
} PubKeyMAC;


ASN1_SEQUENCE(PubKeyMAC) = {
    ASN1_SIMPLE(PubKeyMAC, PubKeyName, ASN1_PRINTABLESTRING),
    ASN1_SIMPLE(PubKeyMAC, MACKey, ASN1_OCTET_STRING),
    ASN1_SIMPLE(PubKeyMAC, MACValue, ASN1_OCTET_STRING)
} ASN1_SEQUENCE_END(PubKeyMAC);

DECLARE_ASN1_FUNCTIONS(PubKeyMAC);
IMPLEMENT_ASN1_FUNCTIONS(PubKeyMAC);


int compute_gmac(SecureProfile* entity);
int validate_autenticity(SecureProfile* entity);

int compute_gmac(SecureProfile* entity)
{
    int ret = 0;
    unsigned char* pub_key_data = NULL;
    size_t pub_key_len = 0;
    unsigned char sym_key[32] = { 0 };
    time_t base_time = 1115240705; /* 05/05/2005 05:05:05 UTC */
    time_t diff_time = entity->generation_timestamp - base_time;
    char mac_path[256] = { 0 };

    // Verifică dacă cheia publică este validă
    if (!entity->public_key) {
        fprintf(stderr, "Public key is NULL\n");
        return 0;
    }

    // Extrage cheia publică în format raw
    pub_key_len = i2d_PUBKEY(entity->public_key, NULL);
    if (pub_key_len <= 0) {
        fprintf(stderr, "Failed to get public key length\n");
        return 0;
    }

    pub_key_data = (unsigned char*)malloc(pub_key_len);
    if (!pub_key_data) {
        fprintf(stderr, "Failed to allocate memory for public key data\n");
        return 0;
    }

    unsigned char* pub_key_ptr = pub_key_data;
    pub_key_len = i2d_PUBKEY(entity->public_key, &pub_key_ptr);
    if (pub_key_len <= 0) {
        fprintf(stderr, "Failed to get public key data\n");
        free(pub_key_data);
        return 0;
    }

    // Generează cheia simetrică cu PKCS5_PBKDF2_HMAC
    if (PKCS5_PBKDF2_HMAC((const char*)&diff_time, sizeof(diff_time), NULL, 0,
        1000, EVP_sha3_256(), 32, sym_key) <= 0) {
        fprintf(stderr, "Failed to derive symmetric key\n");
        free(pub_key_data);
        return 0;
    }

    // AICI ESTE SCHIMBAREA PRINCIPALĂ - GMAC în loc de CMAC
    EVP_CIPHER_CTX* gmac_ctx = EVP_CIPHER_CTX_new();
    if (!gmac_ctx) {
        fprintf(stderr, "Failed to create GMAC context\n");
        free(pub_key_data);
        return 0;
    }

    // Inițializează GMAC (AES-256-GCM fără date criptate)
    if (EVP_EncryptInit_ex(gmac_ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) <= 0) {
        fprintf(stderr, "Failed to initialize GMAC cipher\n");
        free(pub_key_data);
        EVP_CIPHER_CTX_free(gmac_ctx);
        return 0;
    }

    // Setează lungimea IV pentru GCM (standard 12 bytes)
    if (EVP_CIPHER_CTX_ctrl(gmac_ctx, EVP_CTRL_GCM_SET_IVLEN, 12, NULL) <= 0) {
        fprintf(stderr, "Failed to set IV length\n");
        free(pub_key_data);
        EVP_CIPHER_CTX_free(gmac_ctx);
        return 0;
    }

    // IV de zerouri pentru GMAC
    unsigned char iv[12] = { 0 };

    // Setează cheia și IV
    if (EVP_EncryptInit_ex(gmac_ctx, NULL, NULL, sym_key, iv) <= 0) {
        fprintf(stderr, "Failed to set key and IV\n");
        free(pub_key_data);
        EVP_CIPHER_CTX_free(gmac_ctx);
        return 0;
    }

    // Pentru GMAC, folosim doar AAD (Additional Authenticated Data), nu criptăm nimic
    int outlen;
    if (EVP_EncryptUpdate(gmac_ctx, NULL, &outlen, pub_key_data, pub_key_len) <= 0) {
        fprintf(stderr, "Failed to process AAD\n");
        free(pub_key_data);
        EVP_CIPHER_CTX_free(gmac_ctx);
        return 0;
    }

    // Finalizează (nu produce output pentru GMAC)
    if (EVP_EncryptFinal_ex(gmac_ctx, NULL, &outlen) <= 0) {
        fprintf(stderr, "Failed to finalize GMAC\n");
        free(pub_key_data);
        EVP_CIPHER_CTX_free(gmac_ctx);
        return 0;
    }

    // Obține tag-ul GMAC (16 bytes pentru AES-256-GCM)
    entity->gmac_len = 16;
    entity->gmac = (unsigned char*)malloc(entity->gmac_len);
    if (!entity->gmac) {
        fprintf(stderr, "Failed to allocate memory for GMAC\n");
        free(pub_key_data);
        EVP_CIPHER_CTX_free(gmac_ctx);
        return 0;
    }

    if (EVP_CIPHER_CTX_ctrl(gmac_ctx, EVP_CTRL_GCM_GET_TAG, entity->gmac_len, entity->gmac) <= 0) {
        fprintf(stderr, "Failed to get GMAC tag\n");
        free(pub_key_data);
        EVP_CIPHER_CTX_free(gmac_ctx);
        free(entity->gmac);
        entity->gmac = NULL;
        return 0;
    }

    // Eliberez contexte
    EVP_CIPHER_CTX_free(gmac_ctx);
    free(pub_key_data);


    // Creează structura PubKeyMAC
    PubKeyMAC* pub_key_mac = PubKeyMAC_new();
    if (!pub_key_mac) {
        fprintf(stderr, "Failed to create PubKeyMAC\n");
        free(entity->gmac);
        entity->gmac = NULL;
        return 0;
    }

    pub_key_mac->PubKeyName = ASN1_PRINTABLESTRING_new();
    if (!pub_key_mac->PubKeyName) {
        fprintf(stderr, "Failed to create PubKeyName\n");
        PubKeyMAC_free(pub_key_mac);
        free(entity->gmac);
        entity->gmac = NULL;
        return 0;
    }

    pub_key_mac->MACKey = ASN1_OCTET_STRING_new();
    if (!pub_key_mac->MACKey) {
        fprintf(stderr, "Failed to create MACKey\n");
        ASN1_PRINTABLESTRING_free(pub_key_mac->PubKeyName);
        PubKeyMAC_free(pub_key_mac);
        free(entity->gmac);
        entity->gmac = NULL;
        return 0;
    }

    pub_key_mac->MACValue = ASN1_OCTET_STRING_new();
    if (!pub_key_mac->MACValue) {
        fprintf(stderr, "Failed to create MACValue\n");
        ASN1_OCTET_STRING_free(pub_key_mac->MACKey);
        ASN1_PRINTABLESTRING_free(pub_key_mac->PubKeyName);
        PubKeyMAC_free(pub_key_mac);
        free(entity->gmac);
        entity->gmac = NULL;
        return 0;
    }

    if (!ASN1_STRING_set(pub_key_mac->PubKeyName, entity->entity_name, strlen(entity->entity_name))) {
        fprintf(stderr, "Failed to set PubKeyName\n");
        ASN1_OCTET_STRING_free(pub_key_mac->MACValue);
        ASN1_OCTET_STRING_free(pub_key_mac->MACKey);
        ASN1_PRINTABLESTRING_free(pub_key_mac->PubKeyName);
        PubKeyMAC_free(pub_key_mac);
        free(entity->gmac);
        entity->gmac = NULL;
        return 0;
    }

    if (!ASN1_STRING_set(pub_key_mac->MACKey, sym_key, sizeof(sym_key))) {
        fprintf(stderr, "Failed to set MACKey\n");
        ASN1_OCTET_STRING_free(pub_key_mac->MACValue);
        ASN1_OCTET_STRING_free(pub_key_mac->MACKey);
        ASN1_PRINTABLESTRING_free(pub_key_mac->PubKeyName);
        PubKeyMAC_free(pub_key_mac);
        free(entity->gmac);
        entity->gmac = NULL;
        return 0;
    }

    if (!ASN1_STRING_set(pub_key_mac->MACValue, entity->gmac, entity->gmac_len)) {
        fprintf(stderr, "Failed to set MACValue\n");
        ASN1_OCTET_STRING_free(pub_key_mac->MACValue);
        ASN1_OCTET_STRING_free(pub_key_mac->MACKey);
        ASN1_PRINTABLESTRING_free(pub_key_mac->PubKeyName);
        PubKeyMAC_free(pub_key_mac);
        free(entity->gmac);
        entity->gmac = NULL;
        return 0;
    }

    // Codifică în DER
    int der_len = i2d_PubKeyMAC(pub_key_mac, NULL);
    if (der_len <= 0) {
        fprintf(stderr, "Failed to get DER length\n");
        ASN1_OCTET_STRING_free(pub_key_mac->MACValue);
        ASN1_OCTET_STRING_free(pub_key_mac->MACKey);
        ASN1_PRINTABLESTRING_free(pub_key_mac->PubKeyName);
        PubKeyMAC_free(pub_key_mac);
        free(entity->gmac);
        entity->gmac = NULL;
        return 0;
    }

    unsigned char* der_buf = (unsigned char*)malloc(der_len);
    if (!der_buf) {
        fprintf(stderr, "Failed to allocate memory for DER buffer\n");
        ASN1_OCTET_STRING_free(pub_key_mac->MACValue);
        ASN1_OCTET_STRING_free(pub_key_mac->MACKey);
        ASN1_PRINTABLESTRING_free(pub_key_mac->PubKeyName);
        PubKeyMAC_free(pub_key_mac);
        free(entity->gmac);
        entity->gmac = NULL;
        return 0;
    }

    unsigned char* der_ptr = der_buf;
    der_len = i2d_PubKeyMAC(pub_key_mac, &der_ptr);
    if (der_len <= 0) {
        fprintf(stderr, "Failed to encode DER\n");
        free(der_buf);
        ASN1_OCTET_STRING_free(pub_key_mac->MACValue);
        ASN1_OCTET_STRING_free(pub_key_mac->MACKey);
        ASN1_PRINTABLESTRING_free(pub_key_mac->PubKeyName);
        PubKeyMAC_free(pub_key_mac);
        free(entity->gmac);
        entity->gmac = NULL;
        return 0;
    }

    // Eliberez pub_key_mac, nu mai este necesar
    PubKeyMAC_free(pub_key_mac);

    // Salvează în fișier raw
    snprintf(mac_path, sizeof(mac_path), "macs/public_%s.gmac", entity->entity_name);
    BIO* mac_bio = BIO_new_file(mac_path, "wb");
    if (!mac_bio) {
        fprintf(stderr, "Failed to open mac file\n");
        free(der_buf);
        free(entity->gmac);
        entity->gmac = NULL;
        return 0;
    }

    if (BIO_write(mac_bio, der_buf, der_len) != der_len) {
        fprintf(stderr, "Failed to write DER to file\n");
        BIO_free(mac_bio);
        free(der_buf);
        free(entity->gmac);
        entity->gmac = NULL;
        return 0;
    }

    BIO_free(mac_bio);
    free(der_buf);

    log_action(entity->entity_name, "Computed and saved GMAC for public key");

    return 1;
}

int validate_autenticity(SecureProfile* entity)
{
    int ret = 0;
    unsigned char* pub_key_data = NULL;
    size_t pub_key_len = 0;
    unsigned char sym_key[32] = { 0 };
    time_t base_time = 1115240705; /* 05/05/2005 05:05:05 UTC */
    time_t diff_time = entity->generation_timestamp - base_time;
    char gmac_path[256] = { 0 };
    char pub_key_path[256] = { 0 };
    unsigned char* computed_gmac = NULL;
    size_t computed_gmac_len = 0;
    EVP_PKEY* received_public_key = NULL;

    // Verifică dacă entitatea este validă
    if (!entity) {
        fprintf(stderr, "Entity is NULL\n");
        return 0;
    }
    if (!entity->entity_name) {
        fprintf(stderr, "Entity name is NULL\n");
        return 0;
    }

    // Construiește calea către fișierul cheii publice
    snprintf(pub_key_path, sizeof(pub_key_path), "keys/public_%s.pem", entity->entity_name);

    // Citește cheia publică din fișier
    BIO* pub_bio = BIO_new_file(pub_key_path, "r");
    if (!pub_bio) {
        fprintf(stderr, "Failed to open public key file: %s\n", pub_key_path);
        return 0;
    }

    received_public_key = PEM_read_bio_PUBKEY(pub_bio, NULL, NULL, NULL);
    if (!received_public_key) {
        fprintf(stderr, "Failed to read public key from file: %s\n", pub_key_path);
        BIO_free(pub_bio);
        return 0;
    }
    BIO_free(pub_bio);

    // Construiește calea către fișierul GMAC
    snprintf(gmac_path, sizeof(gmac_path), "macs/public_%s.gmac", entity->entity_name);

    // Citește fișierul GMAC și decodează structura PubKeyMAC
    BIO* mac_bio = BIO_new_file(gmac_path, "rb");
    if (!mac_bio) {
        fprintf(stderr, "Failed to open GMAC file: %s\n", gmac_path);
        EVP_PKEY_free(received_public_key);
        return 0;
    }

    // Citește conținutul fișierului GMAC într-un buffer dinamic
    unsigned char* gmac_file_data = NULL;
    int gmac_file_size = 0;
    int buffer_size = 1024; // Dimensiune inițială a buffer-ului
    int bytes_read = 0;

    gmac_file_data = (unsigned char*)malloc(buffer_size);
    if (!gmac_file_data) {
        fprintf(stderr, "Failed to allocate initial memory for GMAC file data\n");
        BIO_free(mac_bio);
        EVP_PKEY_free(received_public_key);
        return 0;
    }

    // Citește fișierul treptat, realocând buffer-ul dacă este necesar
    while ((bytes_read = BIO_read(mac_bio, gmac_file_data + gmac_file_size, buffer_size - gmac_file_size)) > 0) {
        gmac_file_size += bytes_read;
        if (gmac_file_size >= buffer_size - 1) { // Realocă buffer-ul dacă este aproape plin
            buffer_size *= 2;
            unsigned char* temp = (unsigned char*)realloc(gmac_file_data, buffer_size);
            if (!temp) {
                fprintf(stderr, "Failed to reallocate memory for GMAC file data\n");
                free(gmac_file_data);
                BIO_free(mac_bio);
                EVP_PKEY_free(received_public_key);
                return 0;
            }
            gmac_file_data = temp;
        }
    }

    if (bytes_read < 0) {
        fprintf(stderr, "Error reading GMAC file\n");
        free(gmac_file_data);
        BIO_free(mac_bio);
        EVP_PKEY_free(received_public_key);
        return 0;
    }

    BIO_free(mac_bio);

    // Verifică dacă fișierul este gol
    if (gmac_file_size == 0) {
        fprintf(stderr, "GMAC file is empty: %s\n", gmac_path);
        free(gmac_file_data);
        EVP_PKEY_free(received_public_key);
        return 0;
    }

    // Decodează structura PubKeyMAC din format DER
    const unsigned char* gmac_file_ptr = gmac_file_data;
    PubKeyMAC* pub_key_mac = d2i_PubKeyMAC(NULL, &gmac_file_ptr, gmac_file_size);
    if (!pub_key_mac) {
        fprintf(stderr, "Failed to decode PubKeyMAC structure\n");
        free(gmac_file_data);
        EVP_PKEY_free(received_public_key);
        return 0;
    }
    free(gmac_file_data);

    // Extrage cheia simetrică și valoarea GMAC stocată
    unsigned char* stored_sym_key = pub_key_mac->MACKey->data;
    size_t stored_sym_key_len = pub_key_mac->MACKey->length;
    unsigned char* stored_gmac = pub_key_mac->MACValue->data;
    size_t stored_gmac_len = pub_key_mac->MACValue->length;

    // Recalculează cheia simetrică pentru validare suplimentară
    if (PKCS5_PBKDF2_HMAC((const char*)&diff_time, sizeof(diff_time), NULL, 0,
        1000, EVP_sha3_256(), 32, sym_key) <= 0) {
        fprintf(stderr, "Failed to derive symmetric key for verification\n");
        PubKeyMAC_free(pub_key_mac);
        EVP_PKEY_free(received_public_key);
        return 0;
    }

    // Verifică dacă cheia simetrică recalculată se potrivește cu cea stocată
    if (stored_sym_key_len != 32 || memcmp(sym_key, stored_sym_key, 32) != 0) {
        fprintf(stderr, "Symmetric key mismatch\n");
        char log_msg[256];
        snprintf(log_msg, sizeof(log_msg), "GMAC verification failed for %s", entity->entity_name);
        log_action("System", log_msg);
        PubKeyMAC_free(pub_key_mac);
        EVP_PKEY_free(received_public_key);
        return 0;
    }

    // Convertește cheia publică citită în format raw
    pub_key_len = i2d_PUBKEY(received_public_key, NULL);
    if (pub_key_len <= 0) {
        fprintf(stderr, "Failed to get public key length\n");
        PubKeyMAC_free(pub_key_mac);
        EVP_PKEY_free(received_public_key);
        return 0;
    }

    pub_key_data = (unsigned char*)malloc(pub_key_len);
    if (!pub_key_data) {
        fprintf(stderr, "Failed to allocate memory for public key data\n");
        PubKeyMAC_free(pub_key_mac);
        EVP_PKEY_free(received_public_key);
        return 0;
    }

    unsigned char* pub_key_ptr = pub_key_data;
    pub_key_len = i2d_PUBKEY(received_public_key, &pub_key_ptr);
    if (pub_key_len <= 0) {
        fprintf(stderr, "Failed to get public key data\n");
        free(pub_key_data);
        PubKeyMAC_free(pub_key_mac);
        EVP_PKEY_free(received_public_key);
        return 0;
    }

    // AICI ÎNCEPE PARTEA CU GMAC
    EVP_CIPHER_CTX* gmac_ctx = EVP_CIPHER_CTX_new();
    if (!gmac_ctx) {
        fprintf(stderr, "Failed to create GMAC context\n");
        free(pub_key_data);
        PubKeyMAC_free(pub_key_mac);
        EVP_PKEY_free(received_public_key);
        return 0;
    }

    // Inițializează GMAC (AES-256-GCM fără date criptate)
    if (EVP_EncryptInit_ex(gmac_ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) <= 0) {
        fprintf(stderr, "Failed to initialize GMAC cipher\n");
        free(pub_key_data);
        EVP_CIPHER_CTX_free(gmac_ctx);
        PubKeyMAC_free(pub_key_mac);
        EVP_PKEY_free(received_public_key);
        return 0;
    }

    // Setează lungimea IV pentru GCM (standard 12 bytes)
    if (EVP_CIPHER_CTX_ctrl(gmac_ctx, EVP_CTRL_GCM_SET_IVLEN, 12, NULL) <= 0) {
        fprintf(stderr, "Failed to set IV length\n");
        free(pub_key_data);
        EVP_CIPHER_CTX_free(gmac_ctx);
        PubKeyMAC_free(pub_key_mac);
        EVP_PKEY_free(received_public_key);
        return 0;
    }

    // IV de zerouri pentru GMAC
    unsigned char iv[12] = { 0 };

    // Setează cheia și IV
    if (EVP_EncryptInit_ex(gmac_ctx, NULL, NULL, sym_key, iv) <= 0) {
        fprintf(stderr, "Failed to set key and IV\n");
        free(pub_key_data);
        EVP_CIPHER_CTX_free(gmac_ctx);
        PubKeyMAC_free(pub_key_mac);
        EVP_PKEY_free(received_public_key);
        return 0;
    }

    // Pentru GMAC, folosim doar AAD (Additional Authenticated Data), nu criptăm nimic
    int outlen;
    if (EVP_EncryptUpdate(gmac_ctx, NULL, &outlen, pub_key_data, pub_key_len) <= 0) {
        fprintf(stderr, "Failed to process AAD\n");
        free(pub_key_data);
        EVP_CIPHER_CTX_free(gmac_ctx);
        PubKeyMAC_free(pub_key_mac);
        EVP_PKEY_free(received_public_key);
        return 0;
    }

    // Finalizează (nu produce output pentru GMAC)
    if (EVP_EncryptFinal_ex(gmac_ctx, NULL, &outlen) <= 0) {
        fprintf(stderr, "Failed to finalize GMAC\n");
        free(pub_key_data);
        EVP_CIPHER_CTX_free(gmac_ctx);
        PubKeyMAC_free(pub_key_mac);
        EVP_PKEY_free(received_public_key);
        return 0;
    }

    // Obține tag-ul GMAC (16 bytes pentru AES-256-GCM)
    computed_gmac_len = 16;
    computed_gmac = (unsigned char*)malloc(computed_gmac_len);
    if (!computed_gmac) {
        fprintf(stderr, "Failed to allocate memory for computed GMAC\n");
        free(pub_key_data);
        EVP_CIPHER_CTX_free(gmac_ctx);
        PubKeyMAC_free(pub_key_mac);
        EVP_PKEY_free(received_public_key);
        return 0;
    }

    if (EVP_CIPHER_CTX_ctrl(gmac_ctx, EVP_CTRL_GCM_GET_TAG, computed_gmac_len, computed_gmac) <= 0) {
        fprintf(stderr, "Failed to get GMAC tag\n");
        free(computed_gmac);
        free(pub_key_data);
        EVP_CIPHER_CTX_free(gmac_ctx);
        PubKeyMAC_free(pub_key_mac);
        EVP_PKEY_free(received_public_key);
        return 0;
    }

    // Eliberează resursele care nu mai sunt necesare
    EVP_CIPHER_CTX_free(gmac_ctx);
    free(pub_key_data);
    EVP_PKEY_free(received_public_key);

    // Compară GMAC-ul recalculat cu cel stocat
    if (computed_gmac_len != stored_gmac_len || memcmp(computed_gmac, stored_gmac, computed_gmac_len) != 0) {
        fprintf(stderr, "GMAC verification failed: mismatch\n");
        free(computed_gmac);
        PubKeyMAC_free(pub_key_mac);
        return 0;
    }

    // Verificare reușită
    free(computed_gmac);
    PubKeyMAC_free(pub_key_mac);

    char log_msg[256];
    snprintf(log_msg, sizeof(log_msg), "GMAC verified successfully for %s", entity->entity_name);
    log_action("System", log_msg);

    return 1;
}
