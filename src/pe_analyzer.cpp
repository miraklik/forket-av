#include "pe_analyzer.hpp"
#include <stdio.h>
#include <fstream>
#include <string>
#include <iomanip>

bool isPEFile(const std::string& filepath) {
    std::ifstream file(filepath, std::ios::binary);
    if(!file.is_open()) {
        printf("Failed to open file: %s\n", filepath.c_str());
        return false;
    }

    DOS_HEADER dosHeader;
    file.read(reinterpret_cast<char*>(&dosHeader), sizeof(DOS_HEADER));

    if (dosHeader.e_magic != 0x5A4D) {
        return false;
    }

    file.seekg(dosHeader.e_lfanew, std::ios::beg);

    uint32_t peSignature;
    file.read(reinterpret_cast<char*>(&peSignature), sizeof(uint32_t));

    return peSignature == 0x00004550;
}

PEAnalysisResult analyzePEFile(const std::string& filepath) {
    PEAnalysisResult result = {};
    result.isPE = false;
    result.suspicionScore = 0;

    std::ifstream file(filepath, std::ios::binary);
    if(!file.is_open()) {
        result.warnings.push_back("Failed to open file");
        return result;
    }

    DOS_HEADER dosHeader;
    file.read(reinterpret_cast<char*>(&dosHeader), sizeof(DOS_HEADER));

    if (dosHeader.e_magic != 0x5A4D) {
        result.warnings.push_back("Invalid DOS header");
        return result;
    }

    file.seekg(dosHeader.e_lfanew, std::ios::beg);

    PE_HEADER peHeader;
    file.read(reinterpret_cast<char*>(&peHeader), sizeof(PE_HEADER));

    if (peHeader.signature != 0x00004550) {
        result.warnings.push_back("Invalid PE signature");
        return result;
    }

    result.isPE = true;

    if(peHeader.machine == 0x8664) {
        result.is64bit = true;
    }else if (peHeader.machine == 0x014c) {
        result.is64bit = false;
    }else {
        result.warnings.push_back("Invalid machine type");
    }

    file.seekg(peHeader.sizeOfOptionalHeader, std::ios::cur);

    printf("\n=== PE Sections Analysis ===\n");
    printf("Number of sections: %d\n", peHeader.numberOfSections);

    for(int i = 0; i < peHeader.numberOfSections; i++) {
        SECTION_HEADER sectionHeader;
        file.read(reinterpret_cast<char*>(&sectionHeader), sizeof(SECTION_HEADER));

        char section_name[9] = {0};
        memcpy(section_name, sectionHeader.name, 8);

        printf("\nSection %d: %s\n", i + 1, section_name);
        printf("  Virtual Size: 0x%X\n", sectionHeader.virtualSize);
        printf("  Raw Size: 0x%X\n", sectionHeader.sizeOfRawData);
        printf("  Characteristics: 0x%X ", sectionHeader.characteristics);

        bool isCode = sectionHeader.characteristics & IMAGE_SCN_CNT_CODE;
        bool isData = sectionHeader.characteristics & IMAGE_SCN_CNT_INITIALIZED_DATA;
        bool isExecutable = sectionHeader.characteristics & IMAGE_SCN_MEM_EXECUTE;
        bool isReadable = sectionHeader.characteristics & IMAGE_SCN_MEM_READ;
        bool isWritable = sectionHeader.characteristics & IMAGE_SCN_MEM_WRITE;

        printf("(");
        if (isReadable) printf("R");
        if (isWritable) printf("W");
        if (isExecutable) printf("X");
        printf(")\n");

        if (isCode && isWritable && isExecutable) {
            result.hasWritableCodeSection = true;
            result.suspicionScore += 50;
            std::string warning = "SUSPICIOUS: Writable code section (" + 
                                std::string(section_name) + ")";
            result.warnings.push_back(warning);
            printf("  ⚠️  WARNING: Code section is writable (RWX)!\n");
        }

        if (isData && isExecutable && !isCode) {
            result.hasExecutableDataSection = true;
            result.suspicionScore += 30;
            std::string warning = "SUSPICIOUS: Executable data section (" + 
                                std::string(section_name) + ")";
            result.warnings.push_back(warning);
            printf("  ⚠️  WARNING: Data section is executable!\n");
        }

        if (strcmp(section_name, ".packed") == 0 || 
            strcmp(section_name, "UPX0") == 0 ||
            strcmp(section_name, "UPX1") == 0) {
            result.suspicionScore += 20;
            std::string warning = "SUSPICIOUS: Packed section detected (" + 
                                std::string(section_name) + ")";
            result.warnings.push_back(warning);
            printf("  ⚠️  WARNING: Possible packer detected!\n");
        }

        if (sectionHeader.virtualSize > sectionHeader.sizeOfRawData * 10) {
            result.suspicionScore += 15;
            printf("  ⚠️  WARNING: Virtual size >> Raw size (possible unpacking)\n");
        }
    }

    result.hasSuspiciousSections = (result.suspicionScore > 0);

    return result;
}

void printPEInfo(const std::string& filepath) {
    printf("\n=== PE Analysis: %s ===\n", filepath.c_str());

    PEAnalysisResult result = analyzePEFile(filepath);

    if (!result.isPE) {
        printf("File is not a PE file\n");
        return;
    }

    printf("\n=== Summary ===\n");
    printf("Architecture: %s\n", result.is64bit ? "x64" : "x86");
    printf("Suspicion Score: %d/100\n", result.suspicionScore);

    if (result.warnings.empty()) {
        printf("No warnings found\n");
    } else {
        printf("Warnings:\n");
        for (const std::string& warning : result.warnings) {
            printf("  %s\n", warning.c_str());
        }
    }

    printf("\n=== Verdict ===\n");
    if (result.suspicionScore >= 50) {
        printf("🔴 HIGH RISK: This file is highly suspicious!\n");
    } else if (result.suspicionScore >= 20) {
        printf("🟡 MEDIUM RISK: This file has suspicious characteristics\n");
    } else {
        printf("🟢 LOW RISK: This file appears normal\n");
    }
}