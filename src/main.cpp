#include "scanner.hpp"
#include "utils.hpp"
#include "hash.hpp"
#include <stdio.h>
#include <thread>

int main(int argc, char* argv[]) {
    if (argc < 2) {
        printf("Error: No command specified\n\n");
        printHelp();
        return 1;
    }

    std::string command = argv[1];
    unsigned int numThreads = std::thread::hardware_concurrency();

    printf("=== Forket antivirus v1.0 ===\n");
    printf("Threads: %d\n", numThreads);

    if (command == "help" || command == "-h" || command == "--help") {
        printHelp();
        return 0;
    }

    updateSignatures("signatures.txt");
    loadHashDatabase("hashes.txt");

    if (command == "scan") {
        if (argc < 3) {
            printf("Error: No file specified\n\n");
            printHelp();
            return 1;
        }

        std::string filepath = argv[2];
        printf("=== Scanning file: %s ===\n", filepath.c_str());

        bool result = scanFile(filepath);
        return result ? 1 : 0;
    }

    if (command == "scandir") {
        if (argc < 3) {
            std::printf("Error: No directory specified\n");
            std::printf("Usage: antivirus scandir <directory>\n");
            return 1;
        }
        
        std::string dirpath = argv[2];
        
        std::printf("=== Scanning directory: %s ===\n", dirpath.c_str());
        bool result = scanDirParallel(dirpath, numThreads);
        return result ? 1 : 0;
    }

    if (command == "update") {
        if (argc < 3) {
            std::printf("Error: No signature file specified\n");
            std::printf("Usage: antivirus update <sigfile>\n");
            return 1;
        }
        
        std::string sigfile = argv[2];
        std::printf("=== Updating signatures from: %s ===\n", sigfile.c_str());
        
        updateSignatures(sigfile);
        return 0;
    }

    printf("Error: Unknown command '%s'\n\n", command.c_str());
    printHelp();
    return 1;
}