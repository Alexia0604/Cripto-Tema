// input_parser.h
#pragma once

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    char* transaction_id;
    char* sender_id;
    char* receiver_id;
    char* subject;      // NOU: Subiect adăugat
    char* message;
} TransactionInput;

typedef struct {
    int num_entities;
    char** entity_ids;          // Array de ID-uri
    char** entity_passwords;    // NOU: Array de parole
    int num_transactions;
    TransactionInput* transactions;  // Array de tranzacții
} InputData;

InputData* parse_input_file(const char* filename);
void free_input_data(InputData* data);