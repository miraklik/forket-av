#include "scanner.hpp"
#include "utils.hpp"
#include "hash.hpp"
#include "pe_analyzer.hpp"
#include <stdio.h>
#include <thread>
#include <filesystem>

int main(int argc, char* argv[]) {
    printf("=== Forket Antivirus v1.0 ===\n");
    
    if (argc < 2) {
        printf("Error: No command specified\n\n");
        printHelp();
        return 1;
    }

    std::string command = argv[1];

    if (command == "help" || command == "-h" || command == "--help") {
        printHelp();
        return 0;
    }

    if (command == "peinfo") {
        if (argc < 3) {
            printf("Error: No file specified\n");
            printf("Usage: forket peinfo <file>\n");
            return 1;
        }
        
        std::string filepath = argv[2];
        
        if (!std::filesystem::exists(filepath)) {
            printf("Error: File not found: %s\n", filepath.c_str());
            return 1;
        }
        
        printPEInfo(filepath);
        return 0;
    }

    unsigned int numThreads = std::thread::hardware_concurrency();
    printf("CPU cores detected: %d\n", numThreads);
    
    printf("\n=== Loading databases ===\n");
    updateSignatures("signatures.txt");
    loadHashDatabase("hashes.txt");
    printf("\n");

    if (command == "scan") {
        if (argc < 3) {
            printf("Error: No file specified\n");
            printf("Usage: forket scan <file>\n");
            return 1;
        }

        std::string filepath = argv[2];
        
        if (!std::filesystem::exists(filepath)) {
            printf("Error: File not found: %s\n", filepath.c_str());
            return 1;
        }

        printf("=== Scanning file: %s ===\n", filepath.c_str());
        bool result = scanFile(filepath);
        
        printf("\n=== Scan Complete ===\n");
        if (result) {
            printf("🔴 THREAT DETECTED!\n");
        } else {
            printf("✅ File is clean\n");
        }
        
        return result ? 1 : 0;
    }

    if (command == "scandir") {
        if (argc < 3) {
            printf("Error: No directory specified\n");
            printf("Usage: forket scandir <directory> [threads]\n");
            return 1;
        }
        
        std::string dirpath = argv[2];
        
        if (!std::filesystem::exists(dirpath)) {
            printf("Error: Directory not found: %s\n", dirpath.c_str());
            return 1;
        }
        
        if (!std::filesystem::is_directory(dirpath)) {
            printf("Error: Not a directory: %s\n", dirpath.c_str());
            return 1;
        }
        
        if (argc >= 4) {
            int userThreads = std::atoi(argv[3]);
            if (userThreads > 0 && userThreads <= 32) {
                numThreads = userThreads;
            } else {
                printf("Warning: Invalid thread count, using %d threads\n", numThreads);
            }
        }
        
        printf("=== Scanning directory: %s ===\n", dirpath.c_str());
        printf("Using %d threads\n\n", numThreads);
        
        bool result = scanDirParallel(dirpath, numThreads);
        return result ? 1 : 0;
    }

    if (command == "update") {
        if (argc < 3) {
            printf("Error: No signature file specified\n");
            printf("Usage: forket update <sigfile>\n");
            return 1;
        }
        
        std::string sigfile = argv[2];
        
        if (!std::filesystem::exists(sigfile)) {
            printf("Error: Signature file not found: %s\n", sigfile.c_str());
            return 1;
        }
        
        printf("=== Updating signatures from: %s ===\n", sigfile.c_str());
        updateSignatures(sigfile);
        
        printf("✅ Signatures updated successfully\n");
        return 0;
    }

    printf("Error: Unknown command '%s'\n\n", command.c_str());
    printHelp();
    return 1;
}