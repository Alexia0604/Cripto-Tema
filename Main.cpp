#pragma warning(disable:4996)

#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "ws2_32.lib")

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <direct.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/bio.h>
#include <openssl/hmac.h>
#include <openssl/cmac.h>
#include <openssl/asn1.h>
#include <openssl/asn1t.h>
#include <openssl/objects.h>
#include <openssl/ecdh.h>
#include <openssl/applink.c>
#include <openssl/aes.h>

typedef struct {
    char* entity_id;
    EVP_PKEY* private_key;
    EVP_PKEY* public_key;
    unsigned char* gmac;
    size_t gmac_len;
    time_t generation_timestamp;
} SecureProfile;

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

void create_output_dirs() {
    if (_mkdir("keys") == -1 && errno != EEXIST) {
        fprintf(stderr, "Eroare creare director keys: %s\n", strerror(errno));
    }
    if (_mkdir("macs") == -1 && errno != EEXIST) {
        fprintf(stderr, "Eroare creare director keys: %s\n", strerror(errno));
    }
    printf("Directoarele au fost create in keys\n");
}

SecureProfile* create_SecureProfile(const char* id) {
    SecureProfile* entity = (SecureProfile*)malloc(sizeof(SecureProfile));
    if (!entity) return NULL;

    entity->entity_id = strdup(id);
    entity->private_key = NULL;
    entity->public_key = NULL;
    entity->gmac = NULL;    
    entity->gmac_len = 0;       
    entity->generation_timestamp = time(NULL);
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
        goto cleanup;
    }

    printf("Generated key with curve NID_X9_62_prime256v1\n");

    ret = 1;
cleanup:
    if (ctx) EVP_PKEY_CTX_free(ctx);
    return ret;
}

int save_entity_keys(SecureProfile* entity) {
    BIO* private_bio = NULL;
    BIO* public_bio = NULL;
    char private_path[256], public_path[256];
    int ret = 0;
    const char* password = "password";

    create_output_dirs();

    snprintf(private_path, sizeof(private_path), "keys/private_%s.pem", entity->entity_id);
    snprintf(public_path, sizeof(public_path), "keys/public_%s.pem", entity->entity_id);

    private_bio = BIO_new_file(private_path, "w");
    public_bio = BIO_new_file(public_path, "w");

    if (!private_bio || !public_bio) {
        fprintf(stderr, "Failed to open BIO files\n");
        goto cleanup;
    }

    if (!PEM_write_bio_PrivateKey(private_bio, entity->private_key, EVP_aes_256_cbc(), (unsigned char*)password, strlen(password), NULL, NULL)) {
        fprintf(stderr, "Failed to save private key\n");
        goto cleanup;
    }

    if (!PEM_write_bio_PUBKEY(public_bio, entity->private_key)) {
        fprintf(stderr, "Failed to save public key!\n");
        goto cleanup;
    }

    ret = 1;

cleanup:
    if (private_bio) BIO_free(private_bio);
    if (public_bio) BIO_free(public_bio);
    return ret;
}

int compute_gmac(SecureProfile* entity) {
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
    if (PKCS5_PBKDF2_HMAC((const char*)&diff_time, sizeof(diff_time), NULL, 0, 1000, EVP_sha3_256(), 32, sym_key) <= 0) {
        fprintf(stderr, "Failed to derive symmetric key\n");
        free(pub_key_data);
        return 0;
    }

    // Calculează CMAC
    CMAC_CTX* cmac_ctx = CMAC_CTX_new();
    if (!cmac_ctx) {
        fprintf(stderr, "Failed to create CMAC context\n");
        free(pub_key_data);
        return 0;
    }

    if (CMAC_Init(cmac_ctx, sym_key, sizeof(sym_key), EVP_aes_256_cbc(), NULL) <= 0) {
        fprintf(stderr, "Failed to initialize CMAC\n");
        free(pub_key_data);
        CMAC_CTX_free(cmac_ctx);
        return 0;
    }

    if (CMAC_Update(cmac_ctx, pub_key_data, pub_key_len) <= 0) {
        fprintf(stderr, "Failed to update CMAC\n");
        free(pub_key_data);
        CMAC_CTX_free(cmac_ctx);
        return 0;
    }

    if (CMAC_Final(cmac_ctx, NULL, &entity->gmac_len) <= 0) {
        fprintf(stderr, "Failed to get CMAC length\n");
        free(pub_key_data);
        CMAC_CTX_free(cmac_ctx);
        return 0;
    }

    entity->gmac = (unsigned char*)malloc(entity->gmac_len);
    if (!entity->gmac) {
        fprintf(stderr, "Failed to allocate memory for CMAC\n");
        free(pub_key_data);
        CMAC_CTX_free(cmac_ctx);
        return 0;
    }

    if (CMAC_Final(cmac_ctx, entity->gmac, &entity->gmac_len) <= 0) {
        fprintf(stderr, "Failed to compute CMAC\n");
        free(pub_key_data);
        CMAC_CTX_free(cmac_ctx);
        free(entity->gmac);
        entity->gmac = NULL;
        return 0;
    }

    // Eliberez cmac_ctx și pub_key_data, nu mai sunt necesare
    CMAC_CTX_free(cmac_ctx);
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

    if (!ASN1_STRING_set(pub_key_mac->PubKeyName, entity->entity_id, strlen(entity->entity_id))) {
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
    snprintf(mac_path, sizeof(mac_path), "macs/public_%s.gmac", entity->entity_id);
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
    return 1;
}

int read_keys(const char* privateKeyFilename, const char* pubKeyFilename, EVP_PKEY** pkey, EVP_PKEY** peerkey)
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
    if (!PEM_read_PrivateKey(fp, pkey, NULL, NULL)) {
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

int extract_coordinates(EVP_PKEY* pkey, EVP_PKEY* peerkey, unsigned char** x_bytes, size_t* x_len, unsigned char** y_bytes, size_t* y_len) {
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

    // Calculează punctul ECDH: shared_point = priv_key * peer_point
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

    // Calculează SymRight din coordonata y: PBKDF2 cu SHA-384, fără salt
    size_t symRightLen = 32;
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

    // Calculează SymKey: XOR între SymLeft și primii 16 octeți din SymRight
    *symKey = (unsigned char*)malloc(16);
    if (!*symKey) {
        fprintf(stderr, "Failed to allocate memory for SymKey\n");
        free(symLeft);
        free(symRight);
        return 0;
    }
    for (int i = 0; i < 16; i++) {
        (*symKey)[i] = symLeft[i] ^ symRight[i];
    }

    // Returnează octeții neutilizați din SymRight
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

unsigned char* ecdh(const char* ecPrivateKeyFilename, const char* ecPubKeyFilename, unsigned char** symRightUnused, size_t* symRightUnusedLen) {
    EVP_PKEY* pkey = NULL;
    EVP_PKEY* peerkey = NULL;
    unsigned char* x_bytes = NULL;
    size_t x_len;
    unsigned char* y_bytes = NULL;
    size_t y_len;
    unsigned char* symKey = NULL;

    // Citește cheile
    if (!read_keys(ecPrivateKeyFilename, ecPubKeyFilename, &pkey, &peerkey)) {
        return NULL;
    }

    // Extrage coordonatele x și y
    if (!extract_coordinates(pkey, peerkey, &x_bytes, &x_len, &y_bytes, &y_len)) {
        EVP_PKEY_free(pkey);
        EVP_PKEY_free(peerkey);
        return NULL;
    }

    // Derivă cheia simetrică SymKey
    if (!derive_symmetric_key(x_bytes, x_len, y_bytes, y_len, &symKey, symRightUnused, symRightUnusedLen)) {
        free(x_bytes);
        free(y_bytes);
        EVP_PKEY_free(pkey);
        EVP_PKEY_free(peerkey);
        return NULL;
    }

    // Eliberează resursele temporare
    free(x_bytes);
    free(y_bytes);
    EVP_PKEY_free(pkey);
    EVP_PKEY_free(peerkey);

    return symKey;
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
    if (!entity->entity_id) {
        fprintf(stderr, "Entity ID is NULL\n");
        return 0;
    }

    // Construiește calea către fișierul cheii publice
    snprintf(pub_key_path, sizeof(pub_key_path), "keys/public_%s.pem", entity->entity_id);

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
    snprintf(gmac_path, sizeof(gmac_path), "macs/public_%s.gmac", entity->entity_id);

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
    if (PKCS5_PBKDF2_HMAC((const char*)&diff_time, sizeof(diff_time), NULL, 0, 1000, EVP_sha3_256(), 32, sym_key) <= 0) {
        fprintf(stderr, "Failed to derive symmetric key for verification\n");
        PubKeyMAC_free(pub_key_mac);
        EVP_PKEY_free(received_public_key);
        return 0;
    }

    // Verifică dacă cheia simetrică recalculată se potrivește cu cea stocată
    if (stored_sym_key_len != 32 || memcmp(sym_key, stored_sym_key, 32) != 0) {
        fprintf(stderr, "Symmetric key mismatch\n");
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

    // Calculează GMAC pentru cheia publică citită
    CMAC_CTX* cmac_ctx = CMAC_CTX_new();
    if (!cmac_ctx) {
        fprintf(stderr, "Failed to create CMAC context\n");
        free(pub_key_data);
        PubKeyMAC_free(pub_key_mac);
        EVP_PKEY_free(received_public_key);
        return 0;
    }

    if (CMAC_Init(cmac_ctx, sym_key, sizeof(sym_key), EVP_aes_256_cbc(), NULL) <= 0) {
        fprintf(stderr, "Failed to initialize CMAC\n");
        free(pub_key_data);
        CMAC_CTX_free(cmac_ctx);
        PubKeyMAC_free(pub_key_mac);
        EVP_PKEY_free(received_public_key);
        return 0;
    }

    if (CMAC_Update(cmac_ctx, pub_key_data, pub_key_len) <= 0) {
        fprintf(stderr, "Failed to update CMAC\n");
        free(pub_key_data);
        CMAC_CTX_free(cmac_ctx);
        PubKeyMAC_free(pub_key_mac);
        EVP_PKEY_free(received_public_key);
        return 0;
    }

    if (CMAC_Final(cmac_ctx, NULL, &computed_gmac_len) <= 0) {
        fprintf(stderr, "Failed to get computed GMAC length\n");
        free(pub_key_data);
        CMAC_CTX_free(cmac_ctx);
        PubKeyMAC_free(pub_key_mac);
        EVP_PKEY_free(received_public_key);
        return 0;
    }

    computed_gmac = (unsigned char*)malloc(computed_gmac_len);
    if (!computed_gmac) {
        fprintf(stderr, "Failed to allocate memory for computed GMAC\n");
        free(pub_key_data);
        CMAC_CTX_free(cmac_ctx);
        PubKeyMAC_free(pub_key_mac);
        EVP_PKEY_free(received_public_key);
        return 0;
    }

    if (CMAC_Final(cmac_ctx, computed_gmac, &computed_gmac_len) <= 0) {
        fprintf(stderr, "Failed to compute GMAC\n");
        free(computed_gmac);
        free(pub_key_data);
        CMAC_CTX_free(cmac_ctx);
        PubKeyMAC_free(pub_key_mac);
        EVP_PKEY_free(received_public_key);
        return 0;
    }

    // Eliberează resursele care nu mai sunt necesare
    CMAC_CTX_free(cmac_ctx);
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
    return 1;
}

int generate_handshake(SecureProfile* entity1, SecureProfile* entity2)
{
    char private_path_1[256], public_path_1[256];
    char private_path_2[256], public_path_2[256];
    unsigned char* symRightUnused1 = NULL;
    size_t symRightUnusedLentgh1 = 0;
    unsigned char* symRightUnused2 = NULL;
    size_t symRightUnusedLentgh2 = 0;
    unsigned char* symKey1 = NULL;
    unsigned char* symKey2 = NULL;

    snprintf(private_path_1, sizeof(private_path_1), "keys/private_%s.pem", entity1->entity_id);
    snprintf(public_path_1, sizeof(public_path_1), "keys/public_%s.pem", entity1->entity_id);
    
    snprintf(private_path_2, sizeof(private_path_2), "keys/private_%s.pem", entity2->entity_id);
    snprintf(public_path_2, sizeof(public_path_2), "keys/public_%s.pem", entity2->entity_id);

    printf("Verifying authenticity of %s's public key...\n", entity2->entity_id);
    if (!validate_autenticity(entity2))
    {
        fprintf(stderr, "Failed to validate authenticity of %s's public key\n", entity2->entity_id);
        return 0;
    }

    printf("Verifying authenticity of %s's public key...\n", entity1->entity_id);
    if (!validate_autenticity(entity1)) 
    {
        fprintf(stderr, "Failed to validate authenticity of %s's public key\n", entity1->entity_id);
        return 0;
    }

    printf("%s switches keys with %s...\n", entity1->entity_id, entity2->entity_id);
    unsigned char* skey1 = ecdh(private_path_1, public_path_2,&symRightUnused1,&symRightUnusedLentgh1);
    if (!skey1)
    {
        fprintf(stderr, "ECDH failed for %s\n", entity1->entity_id);
        return 0;
    }

    printf("%s switches keys with %s...\n", entity2->entity_id, entity1->entity_id);
    unsigned char* skey2 = ecdh(private_path_2, public_path_1,&symRightUnused2,&symRightUnusedLentgh2);
    if (!skey2) 
    {
        fprintf(stderr, "ECDH failed for %s\n", entity2->entity_id);
        free(symRightUnused1);
        OPENSSL_free(skey1);
        return 0;
    }

    if (symKey1 && symKey2 && memcmp(symKey1, symKey2, 16) == 0) {
        printf("Handshake successful! SymKey generated:\n");
        for (int i = 0; i < 16; i++) {
            printf("%02x ", symKey1[i]);
        }
        printf("\nSymRight unused bytes for %s: %zu bytes\n", entity1->entity_id, symRightUnusedLentgh1);
        for (size_t i = 0; i < symRightUnusedLentgh1; i++) {
            printf("%02x ", symRightUnused1[i]);
        }
        printf("\nSymRight unused bytes for %s: %zu bytes\n", entity2->entity_id, symRightUnusedLentgh2);
        for (size_t i = 0; i < symRightUnusedLentgh2; i++) {
            printf("%02x ", symRightUnused2[i]);
        }
        printf("\n");
    }
    else {
        fprintf(stderr, "Handshake failed: symmetric keys do not match!\n");
        free(symRightUnused1);
        free(symRightUnused2);
        OPENSSL_free(symKey1);
        OPENSSL_free(symKey2);
        return 0;
    }

 
    free(symRightUnused1);
    free(symRightUnused2);
    OPENSSL_free(symKey1);
    OPENSSL_free(symKey2);

    return 1;
}

int main()
{
    SecureProfile* entity1 = create_SecureProfile("entity1");
    SecureProfile* entity2 = create_SecureProfile("entity2");
    if (!entity1 || !entity2) {
        fprintf(stderr, "Failed to create entity\n");
        return 1;
    }

    printf("Generating EC key...\n");
    if (!generate_entity_keys(entity1) || !generate_entity_keys(entity2)) {
        fprintf(stderr, "Key generation failed!\n");
        goto cleanup;
    }

    entity1->public_key = entity1->private_key;
    entity2->public_key = entity2->private_key;

    printf("Saving keys to pem directory...\n");
    if (!save_entity_keys(entity1) || !save_entity_keys(entity2)) {
        fprintf(stderr, "Saving keys failed!\n");
        goto cleanup;
    }

    printf("Computing and saving GMAC...\n");
    if (!compute_gmac(entity1) || !compute_gmac(entity2)) {
        fprintf(stderr, "GMAC computation failed!\n");
        goto cleanup;
    }

    printf("Success to generate and save keys!\n");

    printf("Handshake initialize...\n");
    if (!generate_handshake(entity1, entity2))
    {
        goto cleanup;
    }

    return 0;

cleanup:
    if (entity1){
        if (entity1->private_key) EVP_PKEY_free(entity1->private_key);
        if (entity1->public_key && entity1->public_key != entity1->private_key) EVP_PKEY_free(entity1->public_key);
        if (entity1->gmac) free(entity1->gmac);
        if (entity1->entity_id) free(entity1->entity_id);
        free(entity1);
    }
    if (entity2) {
        if (entity2->private_key) EVP_PKEY_free(entity2->private_key);
        if (entity2->public_key && entity2->public_key != entity2->private_key) EVP_PKEY_free(entity2->public_key);
        if (entity2->gmac) free(entity2->gmac);
        if (entity2->entity_id) free(entity2->entity_id);
        free(entity2);
    }
    return 1;
}