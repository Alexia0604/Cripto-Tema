﻿#pragma warning(disable:4996)

#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "ws2_32.lib")

#include <openssl/applink.c>

#include "input_parser.h"
#include "logging.h"
#include "secure_profile.h" 
#include "gmac_operations.h"
#include "file_operations.h"
#include "crypto_operations.h"
#include "transaction.h"


SecureProfile* find_entity_by_id(SecureProfile** entities, int num_entities, const char* id) {
    for (int i = 0; i < num_entities; i++) {
        if (strcmp(entities[i]->entity_name, id) == 0) {
            return entities[i];
        }
    }
    return NULL;
}

int main(int argc, char* argv[]) 
{
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <input_file>\n", argv[0]);
        return 1;
    }

    InputData* input_data = parse_input_file(argv[1]);
    if (!input_data) {
        fprintf(stderr, "Failed to parse input file\n");
        return 1;
    }

    log_action("System", "Application started");
    create_output_dirs();
    log_action("System", "Created output directories");

    SecureProfile** entities = (SecureProfile**)malloc(
        input_data->num_entities * sizeof(SecureProfile*));
    if (!entities) {
        free_input_data(input_data);
        return 1;
    }

    for (int i = 0; i < input_data->num_entities; i++) 
    {
        entities[i] = create_SecureProfile(input_data->entity_ids[i], input_data->entity_passwords[i],i + 1);

        if (!entities[i]) {
            fprintf(stderr, "Failed to create entity: %s\n", input_data->entity_ids[i]);
            for (int j = 0; j < i; j++) {
                if (entities[j]->entity_name) free(entities[j]->entity_name);
                if (entities[j]->password) free(entities[j]->password);
                free(entities[j]);
            }
            free(entities);
            free_input_data(input_data);
            return 1;
        }

        // Generează cheile EC
        printf("Generating EC key for %s...\n", entities[i]->entity_name);
        if (!generate_entity_keys(entities[i])) 
        {
            fprintf(stderr, "EC key generation failed for entity: %s\n",
                entities[i]->entity_name);
            return 1;
        }

        // Generează cheile RSA
        printf("Generating RSA keys for %s...\n", entities[i]->entity_name);
        if (!generate_rsa_keys(entities[i])) 
        {
            fprintf(stderr, "RSA key generation failed for entity: %s\n",
                entities[i]->entity_name);
            return 1;
        }

        printf("Computing GMAC for RSA key of %s...\n", entities[i]->entity_name);
        if (!compute_gmac_rsa(entities[i])) {
            fprintf(stderr, "RSA GMAC computation failed for entity: %s\n",
                entities[i]->entity_name);
            return 1;
        }

        // Calculează GMAC pentru cheia publică EC
        printf("Computing GMAC for %s...\n", entities[i]->entity_name);
        if (!compute_gmac(entities[i])) {
            fprintf(stderr, "GMAC computation failed for entity: %s\n",
                entities[i]->entity_name);
            // Cleanup
            return 1;
        }
    }

    printf("\n=== All entities created and keys generated ===\n");


    // Procesează tranzacțiile din input
    printf("\n=== Processing transactions ===\n");
    for (int i = 0; i < input_data->num_transactions; i++) {
        TransactionInput* tr = &input_data->transactions[i];

        SecureProfile* sender = find_entity_by_id(entities,
            input_data->num_entities, tr->sender_id);
        SecureProfile* receiver = find_entity_by_id(entities,
            input_data->num_entities, tr->receiver_id);

        if (!sender || !receiver) {
            fprintf(stderr, "Transaction %s: Invalid sender or receiver ID\n",
                tr->transaction_id);
            continue;
        }

        printf("\nProcessing transaction %s from %s to %s...\n",
            tr->transaction_id, sender->entity_name, receiver->entity_name);

        int sym_id = get_sym_elements_id_for_transaction(sender->entity_id, receiver->entity_id);

        if (sym_id == -1) 
        {
            printf("No handshake found between %s and %s, performing handshake...\n",
                sender->entity_name, receiver->entity_name);

            char* password1 = NULL;
            char* password2 = NULL;

            for (int j = 0; j < input_data->num_entities; j++) {
                if (strcmp(input_data->entity_ids[j], sender->entity_name) == 0) {
                    password1 = input_data->entity_passwords[j];
                }
                if (strcmp(input_data->entity_ids[j], receiver->entity_name) == 0) {
                    password2 = input_data->entity_passwords[j];
                }
            }

            if (!password1 || !password2) {
                fprintf(stderr, "Failed to find passwords for handshake\n");
                continue;
            }

            if (!generate_handshake(sender, receiver)) {
                fprintf(stderr, "Handshake failed between %s and %s!\n",
                    sender->entity_name, receiver->entity_name);
                continue;
            }

            printf("Handshake completed successfully!\n");
        }
        else {
            printf("Using existing handshake (SymElements ID: %d)\n", sym_id);
        }

        char transaction_filename[256];
        snprintf(transaction_filename, sizeof(transaction_filename), "%d_%d_%s.trx", sender->entity_id, receiver->entity_id, tr->transaction_id);

        char* sender_password = NULL;
        for (int j = 0; j < input_data->num_entities; j++) {
            if (strcmp(input_data->entity_ids[j], tr->sender_id) == 0) {
                sender_password = input_data->entity_passwords[j];
                break;
            }
        }

        if (!sender_password) 
        {
            fprintf(stderr, "Failed to find password for sender %s\n", tr->sender_id);
            continue;
        }

        if (create_transaction(sender, receiver, tr->subject, tr->message, tr->transaction_id, transaction_filename)) 
        {
            printf("Transaction %s created successfully!\n", tr->transaction_id);

            char rsa_public_key_path[512];
            snprintf(rsa_public_key_path, sizeof(rsa_public_key_path), "keys/%d_pub.rsa", sender->entity_id);

            printf("Verifying transaction %s...\n", tr->transaction_id);
            if (verify_and_read_transaction(transaction_filename, rsa_public_key_path)) 
            {
                printf("Transaction %s verified successfully!\n",
                    tr->transaction_id);
            }
            else {
                fprintf(stderr, "Failed to verify transaction %s\n",
                    tr->transaction_id);
            }
        }
        else {
            fprintf(stderr, "Failed to create transaction %s\n",
                tr->transaction_id);
        }
    }
    printf("\n=== All operations completed! ===\n");
    log_action("System", "Application completed successfully");

    for (int i = 0; i < input_data->num_entities; i++) {
        if (entities[i]) {
            if (entities[i]->entity_name) free(entities[i]->entity_name);
            if (entities[i]->password) free(entities[i]->password);
            if (entities[i]->gmac) free(entities[i]->gmac);
            free(entities[i]);
        }
    }
    free(entities);

    free_input_data(input_data);

    //display_log();

    return 0;
}