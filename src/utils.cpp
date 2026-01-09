#include "utils.hpp"
#include <stdio.h>

void printHelp() {
    printf("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");
    printf("  Forket Antivirus - Command Line Tool\n");
    printf("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n");
    
    printf("USAGE:\n");
    printf("  forket <command> [options]\n\n");
    
    printf("COMMANDS:\n");
    printf("  scan <file>              Scan a single file\n");
    printf("  scandir <dir> [threads]  Scan entire directory\n");
    printf("  peinfo <file>            Analyze PE file structure\n");
    printf("  monitor <dir>            Monitor directory for changes\n");
    printf("  update <sigfile>         Update virus signatures\n");
    printf("  help                     Show this help message\n\n");
    
    printf("EXAMPLES:\n");
    printf("  forket scan test.exe\n");
    printf("  forket scandir /path/to/folder\n");
    printf("  forket peinfo suspicious.exe\n");
    printf("  forket monitor /path/to/folder\n");
    printf("  forket update signatures.txt\n\n");
}