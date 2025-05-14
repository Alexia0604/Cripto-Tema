#pragma once

#include <openssl/asn1.h>
#include <openssl/asn1t.h>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <time.h>
#include "secure_profile.h"
#include "crypto_operations.h"
#include "file_operations.h"
#include "logging.h"


typedef struct Transaction {
    ASN1_INTEGER* TransactionID;
    ASN1_PRINTABLESTRING* Subject;
    ASN1_INTEGER* SenderID;
    ASN1_INTEGER* ReceiverID;
    ASN1_INTEGER* SymElementsID;
    ASN1_OCTET_STRING* EncryptedData;
    ASN1_OCTET_STRING* TransactionSign;
} Transaction;

ASN1_SEQUENCE(Transaction) = {
    ASN1_SIMPLE(Transaction,TransactionID,ASN1_INTEGER),
    ASN1_SIMPLE(Transaction,Subject,ASN1_PRINTABLESTRING),
    ASN1_SIMPLE(Transaction,SenderID,ASN1_INTEGER),
    ASN1_SIMPLE(Transaction,ReceiverID,ASN1_INTEGER),
    ASN1_SIMPLE(Transaction,SymElementsID,ASN1_INTEGER),
    ASN1_SIMPLE(Transaction,EncryptedData,ASN1_OCTET_STRING),
    ASN1_SIMPLE(Transaction,TransactionSign, ASN1_OCTET_STRING)
} ASN1_SEQUENCE_END(Transaction);

DECLARE_ASN1_FUNCTIONS(Transaction);
IMPLEMENT_ASN1_FUNCTIONS(Transaction);


int generate_transaction_id(SecureProfile* sender, SecureProfile* receiver);
int sign_transaction_data(unsigned char* data, size_t data_len, const char* rsa_private_key_file, const char* password, unsigned char** signature, size_t* signature_len);
int create_transaction(SecureProfile* sender, SecureProfile* receiver, const char* subject, const char* message, const char* transaction_id_str, const char* transaction_name);
int verify_and_read_transaction(const char* transaction_name, const char* rsa_public_key_file);

int generate_transaction_id(SecureProfile* sender, SecureProfile* receiver) {
    time_t now = time(NULL);
    struct tm* tm_info = localtime(&now);

    // Formă mai simplă pentru a evita overflow-ul
    int hour_min = tm_info->tm_hour * 60 + tm_info->tm_min;
    int transaction_id = (hour_min * 1000) +
        (sender->entity_id * 10) +
        receiver->entity_id;

    return transaction_id;
}

int sign_transaction_data(unsigned char* data, size_t data_len, const char* rsa_private_key_file, const char* password, unsigned char** signature, size_t* signature_len) {
    BIO* bio = NULL;
    RSA* rsa = NULL;
    EVP_PKEY* rsa_key = NULL;
    EVP_MD_CTX* mdctx = NULL;
    int ret = 0;

    bio = BIO_new_file(rsa_private_key_file, "r");
    if (!bio) {
        fprintf(stderr, "Failed to open RSA private key file\n");
        return 0;
    }

    rsa = PEM_read_bio_RSAPrivateKey(bio, NULL, NULL, (void*)password);
    BIO_free(bio);

    if (!rsa) {
        fprintf(stderr, "Failed to load RSA private key\n");
        return 0;
    }

    // Convertește RSA în EVP_PKEY pentru semnare
    rsa_key = EVP_PKEY_new();
    if (!rsa_key || EVP_PKEY_assign_RSA(rsa_key, rsa) != 1) {
        fprintf(stderr, "Failed to convert RSA to EVP_PKEY\n");
        if (rsa_key) EVP_PKEY_free(rsa_key);
        else RSA_free(rsa);
        return 0;
    }

    mdctx = EVP_MD_CTX_new();
    if (!mdctx) {
        fprintf(stderr, "Failed to create signing context\n");
        EVP_PKEY_free(rsa_key);
        return 0;
    }

    if (EVP_DigestSignInit(mdctx, NULL, EVP_sha256(), NULL, rsa_key) <= 0) {
        fprintf(stderr, "Failed to initialize signing\n");
        EVP_MD_CTX_free(mdctx);
        EVP_PKEY_free(rsa_key);
        return 0;
    }

    if (EVP_DigestSignUpdate(mdctx, data, data_len) <= 0) {
        fprintf(stderr, "Failed to update signing\n");
        EVP_MD_CTX_free(mdctx);
        EVP_PKEY_free(rsa_key);
        return 0;
    }

    if (EVP_DigestSignFinal(mdctx, NULL, signature_len) <= 0) {
        fprintf(stderr, "Failed to get signature length\n");
        EVP_MD_CTX_free(mdctx);
        EVP_PKEY_free(rsa_key);
        return 0;
    }

    *signature = (unsigned char*)malloc(*signature_len);
    if (!*signature) {
        fprintf(stderr, "Failed to allocate memory for signature\n");
        EVP_MD_CTX_free(mdctx);
        EVP_PKEY_free(rsa_key);
        return 0;
    }

    if (EVP_DigestSignFinal(mdctx, *signature, signature_len) <= 0) {
        fprintf(stderr, "Failed to generate signature\n");
        free(*signature);
        *signature = NULL;
        EVP_MD_CTX_free(mdctx);
        EVP_PKEY_free(rsa_key);
        return 0;
    }

    ret = 1;

    EVP_MD_CTX_free(mdctx);
    EVP_PKEY_free(rsa_key);

    return ret;
}

int create_transaction(SecureProfile* sender, SecureProfile* receiver, const char* subject, const char* message, const char* transaction_id_str, const char* transaction_name) {
    Transaction* transaction = NULL;
    unsigned char* symKey = NULL;
    unsigned char* iv = NULL;
    unsigned char* encrypted_data = NULL;
    size_t encrypted_len = 0;
    unsigned char* signature = NULL;
    size_t signature_len = 0;
    unsigned char* der_buf = NULL;
    int der_len = 0;
    BIO* file_bio = NULL;
    int ret = 0;

    char log_msg[256];
    snprintf(log_msg, sizeof(log_msg), "Creating transaction to %s: %s",
        receiver->entity_name, subject);
    log_action(sender->entity_name, log_msg);

    int sym_elements_id = get_sym_elements_id_for_transaction(sender->entity_id, receiver->entity_id);

    char sym_filename[256];
    snprintf(sym_filename, sizeof(sym_filename), "sym/%d.sym", sym_elements_id);
    FILE* test_file = fopen(sym_filename, "r");
    if (!test_file) {
        fprintf(stderr, "No SymElements file found at %s. Need to create handshake first.\n", sym_filename);
        return 0;
    }
    fclose(test_file);

    printf("Looking for SymElements ID: %d\n", sym_elements_id);

    if (!load_sym_elements(sym_elements_id, &symKey, &iv)) {
        fprintf(stderr, "Failed to load SymElements for communication\n");
        return 0;
    }

    if (!aes_128_fancy_ofb_encrypt((unsigned char*)message, strlen(message),
        symKey, iv, &encrypted_data, &encrypted_len)) {
        fprintf(stderr, "Failed to encrypt message\n");
        free(symKey);
        free(iv);
        return 0;
    }

    transaction = Transaction_new();
    if (!transaction) {
        fprintf(stderr, "Failed to create Transaction structure\n");
        free(symKey);
        free(iv);
        free(encrypted_data);
        return 0;
    }

    int transaction_id = atoi(transaction_id_str);

    ASN1_INTEGER_set(transaction->TransactionID, transaction_id);
    ASN1_STRING_set(transaction->Subject, subject, strlen(subject));
    ASN1_INTEGER_set(transaction->SenderID, sender->entity_id);
    ASN1_INTEGER_set(transaction->ReceiverID, receiver->entity_id);
    ASN1_INTEGER_set(transaction->SymElementsID, sym_elements_id);
    ASN1_STRING_set(transaction->EncryptedData, encrypted_data, encrypted_len);

    transaction->TransactionSign = ASN1_OCTET_STRING_new();
    ASN1_STRING_set(transaction->TransactionSign, "", 0);

    int data_to_sign_len = i2d_Transaction(transaction, NULL);
    unsigned char* data_to_sign = (unsigned char*)malloc(data_to_sign_len);
    unsigned char* data_ptr = data_to_sign;
    i2d_Transaction(transaction, &data_ptr);

    char rsa_private_key_path[256];
    snprintf(rsa_private_key_path, sizeof(rsa_private_key_path),
        "keys/%d_priv.rsa", sender->entity_id);

    if (!sign_transaction_data(data_to_sign, data_to_sign_len,
        rsa_private_key_path,sender->password, &signature, &signature_len)) {
        fprintf(stderr, "Failed to sign transaction\n");
        Transaction_free(transaction);
        free(symKey);
        free(iv);
        free(encrypted_data);
        free(data_to_sign);
        return 0;
    }

    ASN1_STRING_set(transaction->TransactionSign, signature, signature_len);

    der_len = i2d_Transaction(transaction, NULL);
    printf("DEBUG: DER length calculated: %d\n", der_len);
    der_buf = (unsigned char*)malloc(der_len);
    unsigned char* der_ptr = der_buf;
    der_len = i2d_Transaction(transaction, &der_ptr);
    printf("DEBUG: DER actually encoded: %d bytes\n", der_len);

    // Debug - afișează primii bytes
    printf("DEBUG: First 10 bytes of DER: ");
    for (int i = 0; i < 10 && i < der_len; i++) {
        printf("%02X ", der_buf[i]);
    }
    printf("\n");

    char output_filename[512];
    snprintf(output_filename, sizeof(output_filename), "transactions/%d_%d_%d.trx",sender->entity_id,receiver->entity_id, transaction_id);

    FILE* file = fopen(output_filename, "wb");
    if (!file) {
        fprintf(stderr, "Failed to open output file: %s\n", output_filename);
        Transaction_free(transaction);
        free(symKey);
        free(iv);
        free(encrypted_data);
        free(data_to_sign);
        free(signature);
        free(der_buf);
        return 0;
    }

    size_t written = fwrite(der_buf, 1, der_len, file);
    if (written != der_len) {
        fprintf(stderr, "Failed to write transaction to file. Written: %zu, Expected: %d\n",
            written, der_len);
        fclose(file);
        Transaction_free(transaction);
        free(symKey);
        free(iv);
        free(encrypted_data);
        free(data_to_sign);
        free(signature);
        free(der_buf);
        return 0;
    }

    printf("Transaction created successfully!\n");
    printf("Transaction ID: %d\n", transaction_id);
    printf("From: %s (ID: %d)\n", sender->entity_name, sender->entity_id);
    printf("To: %s (ID: %d)\n", receiver->entity_name, receiver->entity_id);
    printf("Subject: %s\n", subject);
    printf("Saved to: %s\n", output_filename);

    ret = 1;

    printf("DEBUG: Wrote %zu bytes to %s\n", written, output_filename);

    fclose(file);
    Transaction_free(transaction);
    free(symKey);
    free(iv);
    free(encrypted_data);
    free(data_to_sign);
    free(signature);
    free(der_buf);

    snprintf(log_msg, sizeof(log_msg), "Transaction created successfully (ID: %d) to %s",
        transaction_id, receiver->entity_name);
    log_action(sender->entity_name, log_msg);

    return ret;
}

int verify_and_read_transaction(const char* transaction_name, const char* rsa_public_key_file) {
    FILE* file = NULL;
    Transaction* transaction = NULL;
    unsigned char* file_data = NULL;
    long file_size = 0;
    EVP_PKEY* rsa_key = NULL;
    EVP_MD_CTX* mdctx = NULL;
    unsigned char* decrypted_message = NULL;
    size_t decrypted_len = 0;
    unsigned char* symKey = NULL;
    unsigned char* iv = NULL;
    int ret = 0;

    char transaction_file[512];
    snprintf(transaction_file, sizeof(transaction_file), "transactions/%s", transaction_name);

    // Folosește FILE* pentru citire
    file = fopen(transaction_file, "rb");
    if (!file) {
        fprintf(stderr, "Failed to open transaction file: %s\n", transaction_file);
        return 0;
    }

    // Obține dimensiunea fișierului
    fseek(file, 0, SEEK_END);
    file_size = ftell(file);
    fseek(file, 0, SEEK_SET);
    printf("DEBUG: File size: %ld bytes\n", file_size);

    if (file_size <= 0) {
        fprintf(stderr, "File is empty or error getting size\n");
        fclose(file);
        return 0;
    }

    file_data = (unsigned char*)malloc(file_size);
    if (!file_data) {
        fprintf(stderr, "Failed to allocate memory for file data\n");
        fclose(file);
        return 0;
    }
    
    size_t bytes_read = fread(file_data, 1, file_size, file);
    if (bytes_read != file_size) {
        fprintf(stderr, "Failed to read file. Read: %zu, Expected: %ld\n",
            bytes_read, file_size);
        free(file_data);
        fclose(file);
        return 0;
    }
    fclose(file);

    printf("DEBUG: Read %zu bytes from file\n", bytes_read);
    printf("DEBUG: First 10 bytes: ");
    for (int i = 0; i < 10 && i < file_size; i++) {
        printf("%02X ", file_data[i]);
    }
    printf("\n");

    // Decodează structura Transaction din DER
    const unsigned char* file_ptr = file_data;
    transaction = d2i_Transaction(NULL, &file_ptr, file_size);
    if (!transaction) {
        fprintf(stderr, "Failed to decode transaction\n");

        // Mai mult debugging pentru eroarea OpenSSL
        unsigned long err = ERR_get_error();
        if (err) {
            char err_buf[256];
            ERR_error_string_n(err, err_buf, sizeof(err_buf));
            fprintf(stderr, "OpenSSL error: %s\n", err_buf);
        }

        free(file_data);
        return 0;
    }

    printf("DEBUG: Transaction decoded successfully\n");

    // Citește cheia publică RSA
    BIO* bio = BIO_new_file(rsa_public_key_file, "r");
    if (!bio) {
        fprintf(stderr, "Failed to open RSA public key file\n");
        Transaction_free(transaction);
        free(file_data);
        return 0;
    }

    // Citește RSA public key în format PKCS#1
    RSA* rsa = PEM_read_bio_RSA_PUBKEY(bio, NULL, NULL, NULL);
    BIO_free(bio);

    if (!rsa) {
        fprintf(stderr, "Failed to load RSA public key\n");
        Transaction_free(transaction);
        free(file_data);
        return 0;
    }

    // Convertește în EVP_PKEY
    rsa_key = EVP_PKEY_new();
    if (!rsa_key || EVP_PKEY_assign_RSA(rsa_key, rsa) != 1) {
        fprintf(stderr, "Failed to convert RSA to EVP_PKEY\n");
        RSA_free(rsa);
        Transaction_free(transaction);
        free(file_data);
        return 0;
    }

    // Verifică semnătura
    mdctx = EVP_MD_CTX_new();
    if (!mdctx) {
        fprintf(stderr, "Failed to create verification context\n");
        EVP_PKEY_free(rsa_key);
        Transaction_free(transaction);
        free(file_data);
        return 0;
    }

    if (EVP_DigestVerifyInit(mdctx, NULL, EVP_sha256(), NULL, rsa_key) <= 0) {
        fprintf(stderr, "Failed to initialize verification\n");
        EVP_MD_CTX_free(mdctx);
        EVP_PKEY_free(rsa_key);
        Transaction_free(transaction);
        free(file_data);
        return 0;
    }

    // Temporar elimină semnătura pentru a calcula hash-ul datelor originale
    ASN1_OCTET_STRING* original_sign = transaction->TransactionSign;
    transaction->TransactionSign = ASN1_OCTET_STRING_new();
    ASN1_STRING_set(transaction->TransactionSign, "", 0);

    int data_len = i2d_Transaction(transaction, NULL);
    unsigned char* data = (unsigned char*)malloc(data_len);
    unsigned char* data_ptr = data;
    i2d_Transaction(transaction, &data_ptr);

    // Restaurează semnătura originală
    ASN1_OCTET_STRING_free(transaction->TransactionSign);
    transaction->TransactionSign = original_sign;

    if (EVP_DigestVerifyUpdate(mdctx, data, data_len) <= 0) {
        fprintf(stderr, "Failed to update verification\n");
        free(data);
        EVP_MD_CTX_free(mdctx);
        EVP_PKEY_free(rsa_key);
        Transaction_free(transaction);
        free(file_data);
        return 0;
    }

    int verify_result = EVP_DigestVerifyFinal(mdctx,
        transaction->TransactionSign->data,
        transaction->TransactionSign->length);

    if (verify_result != 1) {
        fprintf(stderr, "Transaction signature verification failed!\n");
        log_action("System", "Transaction signature verification failed");
        free(data);
        EVP_MD_CTX_free(mdctx);
        EVP_PKEY_free(rsa_key);
        Transaction_free(transaction);
        free(file_data);
        return 0;
    }

    printf("Transaction signature verified successfully!\n");
    log_action("System", "Transaction signature verified successfully");

    // Încarcă elementele simetrice pentru decriptare
    int sym_elements_id = ASN1_INTEGER_get(transaction->SymElementsID);
    printf("DEBUG: Loading SymElements with ID: %d\n", sym_elements_id);

    if (!load_sym_elements(sym_elements_id, &symKey, &iv)) {
        fprintf(stderr, "Failed to load SymElements for decryption\n");
        free(data);
        EVP_MD_CTX_free(mdctx);
        EVP_PKEY_free(rsa_key);
        Transaction_free(transaction);
        free(file_data);
        return 0;
    }

    // Decriptează mesajul
    if (!aes_128_fancy_ofb_decrypt(transaction->EncryptedData->data,
        transaction->EncryptedData->length,
        symKey, iv, &decrypted_message, &decrypted_len)) {
        fprintf(stderr, "Failed to decrypt message\n");
        free(symKey);
        free(iv);
        free(data);
        EVP_MD_CTX_free(mdctx);
        EVP_PKEY_free(rsa_key);
        Transaction_free(transaction);
        free(file_data);
        return 0;
    }

    // Afișează detaliile tranzacției
    printf("\n=== Transaction Details ===\n");
    printf("Transaction ID: %ld\n", ASN1_INTEGER_get(transaction->TransactionID));
    printf("Subject: %.*s\n", transaction->Subject->length, transaction->Subject->data);
    printf("Sender ID: %ld\n", ASN1_INTEGER_get(transaction->SenderID));
    printf("Receiver ID: %ld\n", ASN1_INTEGER_get(transaction->ReceiverID));
    printf("SymElements ID: %d\n", sym_elements_id);
    printf("Decrypted Message: %.*s\n", (int)decrypted_len, decrypted_message);
    printf("==========================\n");

    ret = 1;
    char log_msg[256];
    snprintf(log_msg, sizeof(log_msg), "Transaction verified: ID %ld, From ID %ld to ID %ld",
        ASN1_INTEGER_get(transaction->TransactionID),
        ASN1_INTEGER_get(transaction->SenderID),
        ASN1_INTEGER_get(transaction->ReceiverID));
    log_action("System", log_msg);

    // Cleanup
    free(decrypted_message);
    free(symKey);
    free(iv);
    free(data);
    EVP_MD_CTX_free(mdctx);
    EVP_PKEY_free(rsa_key);
    Transaction_free(transaction);
    free(file_data);


    return ret;
}
