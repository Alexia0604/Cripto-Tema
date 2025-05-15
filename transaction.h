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


DECLARE_ASN1_FUNCTIONS(Transaction);

int generate_transaction_id(SecureProfile* sender, SecureProfile* receiver);
int sign_transaction_data(unsigned char* data, size_t data_len, const char* rsa_private_key_file, const char* password, unsigned char** signature, size_t* signature_len);
int create_transaction(SecureProfile* sender, SecureProfile* receiver, const char* subject, const char* message, const char* transaction_id_str, const char* transaction_name);
int verify_and_read_transaction(const char* transaction_name, const char* rsa_public_key_file);