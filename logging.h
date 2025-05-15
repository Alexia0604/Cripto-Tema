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

