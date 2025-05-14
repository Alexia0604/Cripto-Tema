#pragma once

#include <stdio.h>
#include <time.h>
#include <string.h>
#include <direct.h>
#include "file_operations.h"


typedef struct {
    char date[11];
    char time[9];
    char entity[64];
    char action[256];
} LogEntry;


void log_action(const char* entity, const char* action);
void display_log();
void create_output_dirs();

void log_action(const char* entity, const char* action)
{
    FILE* log_file = fopen("logs/activity.blob", "ab");
    if (!log_file) {
        fprintf(stderr, "Failed to open log file\n");
        return;
    }

    LogEntry entry;
    time_t now = time(NULL);
    struct tm* tm_info = localtime(&now);


    strftime(entry.date, sizeof(entry.date), "%Y-%m-%d", tm_info);
    strftime(entry.time, sizeof(entry.time), "%H:%M:%S", tm_info);

    // Copiază entitatea și acțiunea
    strncpy(entry.entity, entity, sizeof(entry.entity) - 1);
    entry.entity[sizeof(entry.entity) - 1] = '\0';
    strncpy(entry.action, action, sizeof(entry.action) - 1);
    entry.action[sizeof(entry.action) - 1] = '\0';

    // Scrie în format binar
    fwrite(&entry, sizeof(LogEntry), 1, log_file);
    fclose(log_file);
}

void display_log() {
    FILE* log_file = fopen("logs/activity.blob", "rb");
    if (!log_file) {
        printf("No log file found\n");
        return;
    }

    LogEntry entry;
    printf("\n=== Activity Log ===\n");
    while (fread(&entry, sizeof(LogEntry), 1, log_file) == 1) {
        printf("[%s %s] %s: %s\n", entry.date, entry.time, entry.entity, entry.action);
    }
    printf("==================\n\n");

    fclose(log_file);
}

void create_output_dirs()
{
    if (_mkdir("keys") == -1 && errno != EEXIST) {
        fprintf(stderr, "Eroare creare director keys: %s\n", strerror(errno));
    }
    if (_mkdir("macs") == -1 && errno != EEXIST) {
        fprintf(stderr, "Eroare creare director macs: %s\n", strerror(errno));
    }
    if (_mkdir("sym") == -1 && errno != EEXIST) {
        fprintf(stderr, "Eroare creare director sym: %s\n", strerror(errno));
    }
    if (_mkdir("transactions") == -1 && errno != EEXIST) {
        fprintf(stderr, "Eroare creare director transactions: %s\n", strerror(errno));
    }
    if (_mkdir("logs") == -1 && errno != EEXIST) {
        fprintf(stderr, "Eroare creare director transactions: %s\n", strerror(errno));
    }
    printf("Directoarele au fost create in keys\n");
}