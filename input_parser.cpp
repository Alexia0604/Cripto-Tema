#pragma warning(disable:4996) 

#include "input_parser.h"

InputData* parse_input_file(const char* filename) {
    FILE* file = fopen(filename, "r");
    if (!file) {
        fprintf(stderr, "Failed to open input file: %s\n", filename);
        return NULL;
    }

    InputData* data = (InputData*)malloc(sizeof(InputData));
    if (!data) {
        fclose(file);
        return NULL;
    }
    data->num_entities = 15;
    
    if (fscanf(file, "%d", &data->num_entities) != 1) 
    {
        fprintf(stderr, "Failed to read number of entities\n");
        fclose(file);
        free(data);
        return NULL;
    }

    data->entity_ids = (char**)malloc(data->num_entities * sizeof(char*));
    data->entity_passwords = (char**)malloc(data->num_entities * sizeof(char*));

    if (!data->entity_ids || !data->entity_passwords) {
        if (data->entity_ids) free(data->entity_ids);
        if (data->entity_passwords) free(data->entity_passwords);
        fclose(file);
        free(data);
        return NULL;
    }

    char line[1024];
    fgets(line, sizeof(line), file);

    for (int i = 0; i < data->num_entities; i++) {
        if (!fgets(line, sizeof(line), file)) {
            fprintf(stderr, "Failed to read entity %d\n", i);
            for (int j = 0; j < i; j++) {
                free(data->entity_ids[j]);
                free(data->entity_passwords[j]);
            }
            free(data->entity_ids);
            free(data->entity_passwords);
            fclose(file);
            free(data);
            return NULL;
        }

        line[strcspn(line, "\n")] = 0;

        char* id = strtok(line, " ");
        char* pass = strtok(NULL, " ");

        if (!id || !pass) {
            fprintf(stderr, "Invalid entity format at line %d. Expected: id password\n", i);
            for (int j = 0; j < i; j++) {
                free(data->entity_ids[j]);
                free(data->entity_passwords[j]);
            }
            free(data->entity_ids);
            free(data->entity_passwords);
            fclose(file);
            free(data);
            return NULL;
        }

        data->entity_ids[i] = strdup(id);
        data->entity_passwords[i] = strdup(pass);

        if (!data->entity_ids[i] || !data->entity_passwords[i]) {
            if (data->entity_ids[i]) free(data->entity_ids[i]);
            if (data->entity_passwords[i]) free(data->entity_passwords[i]);
            for (int j = 0; j < i; j++) {
                free(data->entity_ids[j]);
                free(data->entity_passwords[j]);
            }
            free(data->entity_ids);
            free(data->entity_passwords);
            fclose(file);
            free(data);
            return NULL;
        }
    }

    if (fscanf(file, "%d", &data->num_transactions) != 1) {
        fprintf(stderr, "Failed to read number of transactions\n");
        for (int i = 0; i < data->num_entities; i++) {
            free(data->entity_ids[i]);
            free(data->entity_passwords[i]);
        }
        free(data->entity_ids);
        free(data->entity_passwords);
        fclose(file);
        free(data);
        return NULL;
    }

    data->transactions = (TransactionInput*)malloc(
        data->num_transactions * sizeof(TransactionInput));
    if (!data->transactions) {
        for (int i = 0; i < data->num_entities; i++) {
            free(data->entity_ids[i]);
            free(data->entity_passwords[i]);
        }
        free(data->entity_ids);
        free(data->entity_passwords);
        fclose(file);
        free(data);
        return NULL;
    }

    fgets(line, sizeof(line), file); 

    for (int i = 0; i < data->num_transactions; i++) {
        if (!fgets(line, sizeof(line), file)) {
            fprintf(stderr, "Failed to read transaction %d\n", i);

            for (int j = 0; j < i; j++) {
                free(data->transactions[j].transaction_id);
                free(data->transactions[j].sender_id);
                free(data->transactions[j].receiver_id);
                free(data->transactions[j].subject);
                free(data->transactions[j].message);
            }
            free(data->transactions);
            for (int j = 0; j < data->num_entities; j++) {
                free(data->entity_ids[j]);
                free(data->entity_passwords[j]);
            }
            free(data->entity_ids);
            free(data->entity_passwords);
            fclose(file);
            free(data);
            return NULL;
        }

        line[strcspn(line, "\n")] = 0;

        char line_for_parsing[1024];
        strncpy(line_for_parsing, line, sizeof(line_for_parsing) - 1);
        line_for_parsing[sizeof(line_for_parsing) - 1] = '\0';

        char* tr_id = strtok(line_for_parsing, "/");
        char* sender = strtok(NULL, "/");
        char* receiver = strtok(NULL, "/");
        char* subject = strtok(NULL, "/");
        char* message = strtok(NULL, "");

        if (!tr_id || !sender || !receiver || !subject || !message) {
            fprintf(stderr, "Invalid transaction format at line %d\n", i);
            fprintf(stderr, "Expected: id/sender/receiver/subject/message\n");
            for (int j = 0; j < i; j++) {
                free(data->transactions[j].transaction_id);
                free(data->transactions[j].sender_id);
                free(data->transactions[j].receiver_id);
                free(data->transactions[j].subject);
                free(data->transactions[j].message);
            }
            free(data->transactions);
            for (int j = 0; j < data->num_entities; j++) {
                free(data->entity_ids[j]);
                free(data->entity_passwords[j]);
            }
            free(data->entity_ids);
            free(data->entity_passwords);
            fclose(file);
            free(data);
            return NULL;
        }

        data->transactions[i].transaction_id = strdup(tr_id);
        data->transactions[i].sender_id = strdup(sender);
        data->transactions[i].receiver_id = strdup(receiver);
        data->transactions[i].subject = strdup(subject);
        data->transactions[i].message = strdup(message);

        if (!data->transactions[i].transaction_id ||
            !data->transactions[i].sender_id ||
            !data->transactions[i].receiver_id ||
            !data->transactions[i].subject ||
            !data->transactions[i].message) {
            if (data->transactions[i].transaction_id) free(data->transactions[i].transaction_id);
            if (data->transactions[i].sender_id) free(data->transactions[i].sender_id);
            if (data->transactions[i].receiver_id) free(data->transactions[i].receiver_id);
            if (data->transactions[i].subject) free(data->transactions[i].subject);
            if (data->transactions[i].message) free(data->transactions[i].message);

            for (int j = 0; j < i; j++) {
                free(data->transactions[j].transaction_id);
                free(data->transactions[j].sender_id);
                free(data->transactions[j].receiver_id);
                free(data->transactions[j].subject);
                free(data->transactions[j].message);
            }
            free(data->transactions);
            for (int j = 0; j < data->num_entities; j++) {
                free(data->entity_ids[j]);
                free(data->entity_passwords[j]);
            }
            free(data->entity_ids);
            free(data->entity_passwords);
            fclose(file);
            free(data);
            return NULL;
        }
    }

    fclose(file);
    return data;
}

void free_input_data(InputData* data) {
    if (data) {
        for (int i = 0; i < data->num_transactions; i++) {
            free(data->transactions[i].transaction_id);
            free(data->transactions[i].sender_id);
            free(data->transactions[i].receiver_id);
            free(data->transactions[i].subject);
            free(data->transactions[i].message);
        }
        free(data->transactions);

        for (int i = 0; i < data->num_entities; i++) {
            free(data->entity_ids[i]);
            free(data->entity_passwords[i]);
        }
        free(data->entity_ids);
        free(data->entity_passwords);

        free(data);
    }
}