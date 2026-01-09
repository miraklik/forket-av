#include "scanner.hpp"
#include "utils.hpp"
#include "hash.hpp"
#include "realtime_monitoring.hpp"
#include <stdio.h>
#include <iostream>
#include <string>
#include <thread>
#include <filesystem>
#include <cstdlib>

#ifdef __APPLE__
#include "mach_o.hpp"
#include <CoreServices/CoreServices.h>
#endif

#ifdef _WIN32
#include "pe_analyzer.hpp"
#include <windows.h>
#endif

void onFileEvent(const std::string& path, bool isCreated, bool isModified) {
    if (path.find("/.") != std::string::npos) return;
    printf("\n[MONITOR] Event detected: %s\n", path.c_str());
    
    bool isMalware = scanFile(path);

#ifdef __APPLE__
    if (!isMalware && analyzeMachO(path)) {
        printf("HEURISTIC ALERT: Suspicious Mach-O detected!\n");
        isMalware = true;
    }
#endif

    if (isMalware) printf("THREAT DETECTED!\n");
}

int main(int argc, char* argv[]) {
#ifdef _WIN32
    printf("=== Forket Antivirus v1.0 (Windows Edition) ===\n");
#elif __APPLE__
    printf("=== Forket Antivirus v1.0 (macOS Edition) ===\n");
#else
    printf("=== Forket Antivirus v1.0 (Linux Edition) ===\n");
#endif
    
    if (argc < 2) {
        printHelp();
        return 1;
    }

    std::string command = argv[1];

    if (command == "help" || command == "-h" || command == "--help") {
        printHelp();
        return 0;
    }

#ifdef _WIN32
    if (command == "peinfo") {
        if (argc < 3) return 1;
        printPEInfo(argv[2]);
        return 0;
    }
#endif

#ifdef __APPLE__
    if (command == "machinfo") {
        if (argc < 3) {
            printf("Error: No file specified\n");
            return 1;
        }
        
        bool sus = analyzeMachO(argv[2]);
        if (sus) printf("Suspicious Mach-O file!\n");
        else     printf("Clean Mach-O file.\n");
        return 0;
    }
#endif
    updateSignatures("signatures.txt");
    loadHashDatabase("hashes.txt");

    if (command == "scan") {
        if (argc < 3) {
            printf("Error: No file specified\n");
            return 1;
        }
        std::string path = argv[2];
        
        bool result = scanFile(path);

#ifdef __APPLE__
        if (!result) result = analyzeMachO(path);
#endif

        if (result) printf("THREAT DETECTED!\n");
        else        printf("Clean\n");
        
        return result;
    }

    if (command == "scandir") {
        if (argc < 3) {
            printf("Error: No directory specified\n");
            return 1;
        }
        
        std::string dirpath = argv[2];
        
        if (!std::filesystem::exists(dirpath) || !std::filesystem::is_directory(dirpath)) {
            printf("Error: Invalid directory: %s\n", dirpath.c_str());
            return 1;
        }
        
        unsigned int numThreads = std::thread::hardware_concurrency();
        if (argc >= 4) {
            int userThreads = std::atoi(argv[3]);
            if (userThreads > 0 && userThreads <= 32) {
                numThreads = userThreads;
            }
        }
        
        printf("Scanning directory: %s (%d threads)\n", dirpath.c_str(), numThreads);
        
        bool result = scanDirParallel(dirpath, numThreads);
        
        if (result) printf("Threats were found in directory!\n");
        else        printf("Directory is clean.\n");

        return result ? 1 : 0;
    }

    if (command == "monitor") {
        if (argc < 3) return 1;
        std::string dir = argv[2];
        
        RealTimeMonitoring monitor;
        if (monitor.startMonitoring(dir, onFileEvent)) {
            printf("Monitoring started. Press Ctrl+C to stop.\n");
            
#ifdef __APPLE__
            CFRunLoopRun();
#endif

#ifdef _WIN32
            while(true) std::this_thread::sleep_for(std::chrono::seconds(1));
#endif
        }
        return 0;
    }

    if (command == "update") {
        if (argc < 3) {
            printf("Error: No signature file specified\n");
            return 1;
        }
        
        std::string sigfile = argv[2];
        if (!std::filesystem::exists(sigfile)) {
            printf("Error: Signature file not found: %s\n", sigfile.c_str());
            return 1;
        }
        
        updateSignatures(sigfile);
        printf("Signatures updated successfully from %s\n", sigfile.c_str());
        return 0;
    }

    printf("Error: Unknown command '%s'\n", command.c_str());
    printHelp();
    return 1;
}