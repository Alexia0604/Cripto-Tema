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


DECLARE_ASN1_FUNCTIONS(PubKeyMAC);

int compute_gmac(SecureProfile* entity);
int validate_autenticity(SecureProfile* entity);
int compute_gmac_rsa(SecureProfile* entity);
int validate_autenticity_rsa(SecureProfile* entity);

