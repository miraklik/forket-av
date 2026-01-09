#include "yara_scanner.hpp"
#include <stdio.h>
#include <filesystem>

namespace fs = std::filesystem;

YaraScanner::YaraScanner() : rules(nullptr), compiler(nullptr), initialized(false) {
    if (yr_initialize() == ERROR_SUCCESS) {
        initialized = true;
    }else {
        printf("Failed to initialize YARA\n");
        return;
    }
}

YaraScanner::~YaraScanner() {
    if(rules) yr_rules_destroy(rules);
    if (compiler) yr_compiler_destroy(compiler);
    if (initialized) yr_finalize();
}

bool YaraScanner::loadRules(const std::string& path) {
    if (!initialized) return false;

    if (yr_compiler_create(&compiler) != ERROR_SUCCESS) {
        printf("[YARA] Failed to create compiler\n");
        return false;
    }

    int filesLoaded = 0;

    if (fs::is_directory(path)) {
        printf("[YARA] Loading rules from directory: %s\n", path.c_str());
        for (const auto& entry : fs::recursive_directory_iterator(path)) {
            if (entry.is_regular_file()) {
                std::string ext = entry.path().extension().string();
                if (ext == ".yar" || ext == ".yara") {
                    if (addFileToCompiler(entry.path().string())) {
                        filesLoaded++;
                    }
                }
            }
        }
    } else if (fs::exists(path)) {
        if (addFileToCompiler(path)) {
            filesLoaded++;
        }
    } else {
        printf("[YARA] Invalid path: %s\n", path.c_str());
        return false;
    }

    if (filesLoaded == 0) {
        printf("[YARA] No rule files found.\n");
        return false;
    }

    printf("[YARA] Loaded %d rule files.\n", filesLoaded);

    if (yr_compiler_get_rules(compiler, &rules) != ERROR_SUCCESS) {
        printf("[YARA] Failed to compile rules.\n");
        return false;
    }

    printf("[YARA] Rules compiled successfully.\n");
    return true;
}

int YaraScanner::scanCallback(YR_SCAN_CONTEXT* context, int message, void* message_data, void* user_data) {
    if (message == CALLBACK_MSG_RULE_MATCHING) {
        YR_RULE* rule = (YR_RULE*)message_data;
        printf("Matched rule: %s\n", rule->identifier);
        
        bool* detected = (bool*)user_data;
        *detected = true;
        
        return CALLBACK_ABORT;
    }
    return CALLBACK_CONTINUE;
}

bool YaraScanner::scanFile(const std::string& filepath) {
    if (!rules) {
        printf("No rules loaded\n");
        return false;
    }

    bool detected = false;

    int result = yr_rules_scan_file(
        rules, 
        filepath.c_str(), 
        0, 
        scanCallback, 
        &detected, 
        0
    );

    if (result != ERROR_SUCCESS) {
        printf("Failed to scan file: %s\n", filepath.c_str());
        return false;
    }

    return detected;
}

bool YaraScanner::addFileToCompiler(const std::string& filepath) {
    FILE* file = fopen(filepath.c_str(), "r");
    if (!file) {
        printf("Failed to open file: %s\n", filepath.c_str());
        return false;
    }

    int errors = yr_compiler_add_file(compiler, file, nullptr, filepath.c_str());
    
    fclose(file);

    if (errors > 0) {
        printf("Failed to add file to YARA compiler: %s\n", filepath.c_str());
        return false;
    }
    
    return true;
}