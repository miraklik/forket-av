#include "scanner.hpp"
#include "hash.hpp"
#include <stdio.h>
#include <fstream>
#include <thread>
#include <mutex>
#include <queue>
#include <string>
#include <vector>
#include <atomic>
#include <filesystem>
#include <iostream>

std::mutex queueMutex;
std::mutex outputMutex;
std::queue<std::string> fileQueue;
int totalFiles = 0;
int scannedFiles = 0;
std::atomic<int> virusesFound(0);
std::vector<std::string> virusSignatures = {"\x45\x69\x63\x61\x72"};

bool scanFile(const std::string& filepath) {
    printf("=== Scanning file: %s ===\n", filepath.c_str());

    std::string fileHash = calculateSHA256(filepath);
    if(!fileHash.empty()) {
        printf("File hash: %s\n", fileHash.c_str());

        if(checkDatabase(fileHash)) {
            printf("Virus found in %s\n", filepath.c_str());
            return true;
        }
    }

    std::ifstream file(filepath, std::ios::binary);
    if(!file.is_open()) {
        std::printf("Failed to open file: %s\n", filepath.c_str());
        return false;
    }
    
    std::string file_content((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());

    for(const auto& signature: virusSignatures) {
        size_t pos = file_content.find(signature);
        if (pos != std::string::npos) {
            std::printf("Virus found in %s\n", filepath.c_str());
            return true;
        }
    }

    std::printf("Virus not found in %s\n", filepath.c_str());
    return false;
}

bool scanDirParallel(const std::string& dirpath, int numThreads) {
    try {
        if (!std::filesystem::exists(dirpath)) {
            std::printf("Directory %s does not exist\n", dirpath.c_str());
            return false;
        }

        if (!std::filesystem::is_directory(dirpath)) {
            std::printf("%s is not a directory\n", dirpath.c_str());
            return false;
        }

        totalFiles = 0;
        scannedFiles = 0;
        virusesFound = 0; 
        
        std::queue<std::string> empty;
        std::swap(fileQueue, empty);

        std::printf("=== Collecting files from %s ===\n", dirpath.c_str());

        for(const auto& entry: std::filesystem::recursive_directory_iterator(dirpath)) {
            if (entry.is_regular_file()) {
                fileQueue.push(entry.path().string());
                totalFiles++;
            }
        }

        if (totalFiles == 0) {
            std::printf("No files found in directory\n");
            return false;
        }

        std::printf("Found %d files. Starting scan with %d threads...\n", 
                    totalFiles, numThreads);

        std::vector<std::thread> threads;
        for (int i = 0; i < numThreads; i++) {
            threads.push_back(std::thread(workerThread, i));
        }

        for (auto& t : threads) {
            t.join();
        }

        std::printf("\n=== Scan complete! ===\n");
        std::printf("Total files scanned: %d\n", scannedFiles);
        std::printf("Viruses found: %d\n", virusesFound.load());

        if (virusesFound > 0) {
            std::printf("\n[!] Viruses detected in directory!\n");
            return true;
        } else {
            std::printf("\n[+] Directory is clean\n");
            return false;
        }

    }
    catch(const std::filesystem::filesystem_error& e) {
        std::printf("Filesystem error: %s\n", e.what());
        return false;
    }
    catch(const std::exception& e) {
        std::printf("Error: %s\n", e.what());
        return false;
    }
}

void updateSignatures(const std::string& signaturesFile) {
    std::ifstream file(signaturesFile);

    if(!file.is_open()) {
        std::printf("Failed to open signatures file: %s\n", signaturesFile.c_str());
        return;
    }

    virusSignatures.clear();

    std::string line;
    int count = 0;

    while (std::getline(file, line)) {
        if (!line.empty()) {
            virusSignatures.push_back(line);
            count++;
        }
    }

    std::printf("Loaded %d virus signatures from %s\n", count, signaturesFile.c_str());
}

void workerThread(int threadId) {
    while (true) {
        std::string filepath;

        {
            std::lock_guard<std::mutex> lock(queueMutex);
            if (fileQueue.empty()) {
                break;
            }
            filepath = fileQueue.front();
            fileQueue.pop();
        }

        bool infected = scanFile(filepath);

        {
            std::lock_guard<std::mutex> lock(outputMutex);
            scannedFiles++;
            
            if (infected) {
                virusesFound++; 
                std::cout << "[Thread " << threadId << "] INFECTED: " 
                          << filepath << std::endl;
            }
            
            std::cout << "Progress: " << scannedFiles << "/" << totalFiles 
                      << std::endl;
        }
    }
}