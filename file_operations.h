#pragma once

#include <openssl/asn1.h>
#include <openssl/asn1t.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>


typedef struct SymElements {
    ASN1_INTEGER* SymElementsID;
    ASN1_OCTET_STRING* SymKey;
    ASN1_OCTET_STRING* IV;
} SymElements;

ASN1_SEQUENCE(SymElements) = {
    ASN1_SIMPLE(SymElements,SymElementsID,ASN1_INTEGER),
    ASN1_SIMPLE(SymElements, SymKey,ASN1_OCTET_STRING),
    ASN1_SIMPLE(SymElements, IV,ASN1_OCTET_STRING)
} ASN1_SEQUENCE_END(SymElements);

DECLARE_ASN1_FUNCTIONS(SymElements);
IMPLEMENT_ASN1_FUNCTIONS(SymElements);


int save_sym_elements(unsigned char* symKey, unsigned char* iv, int elementID);
int load_sym_elements(int sym_elements_id, unsigned char** symKey, unsigned char** iv);

int save_sym_elements(unsigned char* symKey, unsigned char* iv, int elementID)
{
    SymElements* sym_elem = SymElements_new();
    BIO* bio = NULL;
    char filename[256];
    int der_len;
    unsigned char* der_buf = NULL;
    int ret = 0;

    ASN1_INTEGER_set(sym_elem->SymElementsID, elementID);
    ASN1_STRING_set(sym_elem->SymKey, symKey, 16);
    ASN1_STRING_set(sym_elem->IV, iv, 16);

    der_len = i2d_SymElements(sym_elem, NULL);
    der_buf = (unsigned char*)malloc(der_len);
    unsigned char* der_ptr = der_buf;
    i2d_SymElements(sym_elem, &der_ptr);

    bio = BIO_new(BIO_s_mem());
    BIO* b64 = BIO_new(BIO_f_base64());
    BIO_push(b64, bio);
    BIO_write(b64, der_buf, der_len);
    BIO_flush(b64);

    snprintf(filename, sizeof(filename), "sym/%d.sym", elementID);
    printf("Saving SymElements to: %s\n", filename);
    BIO* file_bio = BIO_new_file(filename, "w");

    char* base64_data;
    long base64_len = BIO_get_mem_data(bio, &base64_data);
    BIO_write(file_bio, base64_data, base64_len);

    ret = 1;

    BIO_free_all(b64);
    BIO_free(file_bio);
    SymElements_free(sym_elem);
    free(der_buf);

    return ret;
}

int load_sym_elements(int sym_elements_id, unsigned char** symKey, unsigned char** iv)
{
    char filename[256];
    BIO* bio = NULL;
    SymElements* sym_elem = NULL;
    int ret = 0;

    snprintf(filename, sizeof(filename), "sym/%d.sym", sym_elements_id);

    bio = BIO_new_file(filename, "r");
    if (!bio) {
        fprintf(stderr, "Failed to open SymElements file: %s\n", filename);
        return 0;
    }

    BIO* b64 = BIO_new(BIO_f_base64());
    BIO_push(b64, bio);

    char buffer[4096];
    int der_len = BIO_read(b64, buffer, sizeof(buffer));

    if (der_len <= 0) {
        fprintf(stderr, "Failed to read SymElements file\n");
        BIO_free_all(b64);
        return 0;
    }

    const unsigned char* der_ptr = (const unsigned char*)buffer;
    sym_elem = d2i_SymElements(NULL, &der_ptr, der_len);
    if (!sym_elem) {
        fprintf(stderr, "Failed to decode SymElements DER\n");
        BIO_free_all(b64);
        return 0;
    }

    *symKey = (unsigned char*)malloc(sym_elem->SymKey->length);
    *iv = (unsigned char*)malloc(sym_elem->IV->length);

    if (*symKey && *iv) {
        memcpy(*symKey, sym_elem->SymKey->data, sym_elem->SymKey->length);
        memcpy(*iv, sym_elem->IV->data, sym_elem->IV->length);
        ret = 1;
    }

    SymElements_free(sym_elem);
    BIO_free_all(b64);

    return ret;
}
