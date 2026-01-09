#include "scanner.hpp"
#include "utils.hpp"
#include "hash.hpp"
#include "pe_analyzer.hpp"
#include "realtime_monitoring.hpp"
#include <CoreServices/CoreServices.h>
#include <stdio.h>
#include <thread>
#include <filesystem>

void onFileEvent(const std::string& path, bool isCreated, bool isModified) {
    std::string ext = std::filesystem::path(path).extension().string();
    
    if (ext != ".exe" && ext != ".sh" && ext != ".app" && 
        ext != ".dmg" && ext != ".pkg" && ext != ".zip" &&
        ext != ".py" && ext != ".rb" && ext != ".pl") {
        return;
    }
    
    if (isCreated) {
        printf("\nNew file detected: %s\n", path.c_str());
    } else if (isModified) {
        printf("\nFile modified: %s\n", path.c_str());
    }
    
    printf("🔍 Scanning...\n");
    
    bool isMalware = scanFile(path);
    
    if (isMalware) {
        printf("ALERT: MALWARE DETECTED!\n");
        printf("File: %s\n", path.c_str());
    } else {
        printf("File is clean\n");
    }
}

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

    if (command == "monitor" || command == "realtime") {
    if (argc < 3) {
        printf("Error: No directory specified\n");
        printf("Usage: forket monitor <directory>\n");
        return 1;
    }
    
    std::string dirpath = argv[2];
    
    if (!std::filesystem::exists(dirpath)) {
        printf("Error: Directory not found: %s\n", dirpath.c_str());
        return 1;
    }
    
    printf("=== Starting Real-time Protection ===\n");
    printf("Monitoring: %s\n", dirpath.c_str());
    printf("Press Ctrl+C to stop...\n\n");
    
    updateSignatures("signatures.txt");
    loadHashDatabase("hashes.txt");
    
    RealTimeMonitoring monitor;
    
    if (!monitor.startMonitoring(dirpath, onFileEvent)) {
        printf("Error: Failed to start monitoring\n");
        return 1;
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
        
        printf("Signatures updated successfully\n");
        return 0;
    }

    printf("Error: Unknown command '%s'\n\n", command.c_str());
    printHelp();

    CFRunLoopRun();
    return 1;
}