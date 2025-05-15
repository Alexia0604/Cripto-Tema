#pragma once

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    char* transaction_id;
    char* sender_id;
    char* receiver_id;
    char* subject;
    char* message;
} TransactionInput;

typedef struct {
    int num_entities;
    char** entity_ids;
    char** entity_passwords;
    int num_transactions;
    TransactionInput* transactions;
} InputData;

InputData* parse_input_file(const char* filename);
void free_input_data(InputData* data);