#include "utils.hpp"
#include <stdio.h>

void printHelp() {
    printf("Usage: forket <command> [options]\n\n");
    printf("Commands:\n");
    printf("  scan <file>           Scan a single file\n");
    printf("  scandir <directory>   Scan entire directory\n");
    printf("  update <sigfile>      Update virus signatures\n");
    printf("  help                  Show this help message\n\n");
    printf("Examples:\n");
    printf("  forket scan test.exe\n");
    printf("  forket scandir /path/to/folder\n");
    printf("  forket update signatures.txt\n");
}