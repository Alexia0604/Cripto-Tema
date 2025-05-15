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


DECLARE_ASN1_FUNCTIONS(SymElements);


int save_sym_elements(unsigned char* symKey, unsigned char* iv, int elementID);
int load_sym_elements(int sym_elements_id, unsigned char** symKey, unsigned char** iv);