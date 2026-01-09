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
    printf("  scandir <dir>           Scan entire directory\n");
    #ifdef _WIN32
    printf("  peinfo <file>            Analyze PE file structure\n");
    #endif
    printf("  monitor <dir>           Monitor directory for changes\n");
    #ifdef __APPLE__
    printf("  machinfo <file>          Analyze Mach-O file structure\n");
    #endif
    printf("  update <sigfile>         Update virus signatures\n");
    printf("  help                    Show this help message\n\n");
    
    printf("EXAMPLES:\n");
    printf("  forket scan test.exe\n");
    printf("  forket scandir /path/to/folder\n");
    #ifdef _WIN32
    printf("  forket peinfo suspicious.exe\n");
    #endif
    printf("  forket monitor /path/to/folder\n");
    #ifdef __APPLE__
    printf("  forket machinfo suspicious.dylib\n");
    #endif
    printf("  forket update signatures.txt\n\n");
}