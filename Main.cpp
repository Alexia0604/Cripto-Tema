#pragma warning(disable:4996)

#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "ws2_32.lib")

#include <openssl/applink.c>

#include "utils.h"
#include "logging.h"
#include "secure_profile.h" 
#include "gmac_operations.h"
#include "file_operations.h"
#include "crypto_operations.h"
#include "transaction.h"

int main()
{
    log_action("System", "Application started");

    create_output_dirs();

    log_action("System", "Created output directories");

    SecureProfile* entity1 = create_SecureProfile("entity1", 1);
    SecureProfile* entity2 = create_SecureProfile("entity2", 2);
    if (!entity1 || !entity2)
    {
        fprintf(stderr, "Failed to create entity\n");
        log_action("System", "Failed to create entities");

        if (entity1) 
        {
            if (entity1->entity_name) free(entity1->entity_name);
            free(entity1);
        }
        if (entity2) 
        {
            if (entity2->entity_name) free(entity2->entity_name);
            free(entity2);
        }
        return 1;
    }

    log_action("System", "Created entities: entity1 and entity2");

    printf("Generating EC key...\n");
    if (!generate_entity_keys(entity1) || !generate_entity_keys(entity2)) 
    {
        fprintf(stderr, "Key generation failed!\n");
        if (entity1->private_key) EVP_PKEY_free(entity1->private_key);
        if (entity2->private_key) EVP_PKEY_free(entity2->private_key);
        if (entity1->entity_name) free(entity1->entity_name);
        if (entity2->entity_name) free(entity2->entity_name);
        free(entity1);
        free(entity2);
        return 1;
    }

    entity1->public_key = entity1->private_key;
    entity2->public_key = entity2->private_key;

    printf("Saving keys to pem directory...\n");
    if (!save_entity_keys(entity1) || !save_entity_keys(entity2)) 
    {
        fprintf(stderr, "Saving keys failed!\n");
        if (entity1->private_key) EVP_PKEY_free(entity1->private_key);
        if (entity2->private_key) EVP_PKEY_free(entity2->private_key);
        if (entity1->entity_name) free(entity1->entity_name);
        if (entity2->entity_name) free(entity2->entity_name);
        free(entity1);
        free(entity2);
        return 1;
    }

    printf("Generating RSA keys...\n");
    if (!generate_rsa_keys(entity1) || !generate_rsa_keys(entity2)) 
    {
        fprintf(stderr, "RSA key generation failed!\n");
        if (entity1->private_key) EVP_PKEY_free(entity1->private_key);
        if (entity2->private_key) EVP_PKEY_free(entity2->private_key);
        if (entity1->rsa_key) EVP_PKEY_free(entity1->rsa_key);
        if (entity2->rsa_key) EVP_PKEY_free(entity2->rsa_key);
        if (entity1->entity_name) free(entity1->entity_name);
        if (entity2->entity_name) free(entity2->entity_name);
        free(entity1);
        free(entity2);
        return 1;
    }

    printf("Saving RSA keys...\n");
    if (!save_rsa_keys(entity1) || !save_rsa_keys(entity2)) 
    {
        fprintf(stderr, "Saving RSA keys failed!\n");
        if (entity1->private_key) EVP_PKEY_free(entity1->private_key);
        if (entity2->private_key) EVP_PKEY_free(entity2->private_key);
        if (entity1->rsa_key) EVP_PKEY_free(entity1->rsa_key);
        if (entity2->rsa_key) EVP_PKEY_free(entity2->rsa_key);
        if (entity1->entity_name) free(entity1->entity_name);
        if (entity2->entity_name) free(entity2->entity_name);
        free(entity1);
        free(entity2);
        return 1;
    }

    printf("Computing and saving GMAC...\n");
    if (!compute_gmac(entity1) || !compute_gmac(entity2)) 
    {
        fprintf(stderr, "GMAC computation failed!\n");
        if (entity1->private_key) EVP_PKEY_free(entity1->private_key);
        if (entity2->private_key) EVP_PKEY_free(entity2->private_key);
        if (entity1->rsa_key) EVP_PKEY_free(entity1->rsa_key);
        if (entity2->rsa_key) EVP_PKEY_free(entity2->rsa_key);
        if (entity1->gmac) free(entity1->gmac);
        if (entity2->gmac) free(entity2->gmac);
        if (entity1->entity_name) free(entity1->entity_name);
        if (entity2->entity_name) free(entity2->entity_name);
        free(entity1);
        free(entity2);
        return 1;
    }

    printf("Success to generate and save keys!\n");

    printf("Handshake initialize...\n");
    if (!generate_handshake(entity1, entity2)) 
    {
        fprintf(stderr, "Handshake failed!\n");
        if (entity1->private_key) EVP_PKEY_free(entity1->private_key);
        if (entity2->private_key) EVP_PKEY_free(entity2->private_key);
        if (entity1->rsa_key) EVP_PKEY_free(entity1->rsa_key);
        if (entity2->rsa_key) EVP_PKEY_free(entity2->rsa_key);
        if (entity1->gmac) free(entity1->gmac);
        if (entity2->gmac) free(entity2->gmac);
        if (entity1->entity_name) free(entity1->entity_name);
        if (entity2->entity_name) free(entity2->entity_name);
        free(entity1);
        free(entity2);
        return 1;
    }

    printf("\n=== Transaction System Test ===\n");

    const char* message1 = "Transfer 100 RON pentru servicii consultanta";
    const char* subject1 = "Plata servicii";

    if (create_transaction(entity1, entity2, subject1, message1, "transaction_1_to_2.der")) 
    {
        printf("\nTransaction created successfully!\n");

        char rsa_public_key_path[512];
        snprintf(rsa_public_key_path, sizeof(rsa_public_key_path),
            "keys/rsa_public_%s.pem", entity1->entity_name);

        printf("\n=== Verifying Transaction ===\n");
        if (verify_and_read_transaction("transaction_1_to_2.der", rsa_public_key_path)) {
            printf("Transaction verified successfully!\n");
        }
    }

    const char* message2 = "Confirmare plata primita. Multumesc!";
    const char* subject2 = "Confirmare plata";

    if (create_transaction(entity2, entity1, subject2, message2, "transaction_2_to_1.der")) 
    {
        printf("\nSecond transaction created successfully!\n");

        char rsa_public_key_path2[512];
        snprintf(rsa_public_key_path2, sizeof(rsa_public_key_path2),
            "keys/rsa_public_%s.pem", entity2->entity_name);

        printf("\n=== Verifying Second Transaction ===\n");
        if (verify_and_read_transaction("transaction_2_to_1.der", rsa_public_key_path2)) {
            printf("Second transaction verified successfully!\n");
        }
    }

    printf("\n=== All operations completed! ===\n");
    log_action("System", "Application completed successfully");

    if (entity1->private_key) EVP_PKEY_free(entity1->private_key);
    if (entity2->private_key) EVP_PKEY_free(entity2->private_key);
    if (entity1->rsa_key) EVP_PKEY_free(entity1->rsa_key);
    if (entity2->rsa_key) EVP_PKEY_free(entity2->rsa_key);
    if (entity1->gmac) free(entity1->gmac);
    if (entity2->gmac) free(entity2->gmac);
    if (entity1->entity_name) free(entity1->entity_name);
    if (entity2->entity_name) free(entity2->entity_name);
    free(entity1);
    free(entity2);

    display_log();

    return 0;
}