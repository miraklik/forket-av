#ifndef PE_ANALYZER_HPP
#define PE_ANALYZER_HPP

#include <string>
#include <vector>
#include <cstdint>

struct DOS_HEADER {
    uint16_t e_magic;
    uint8_t e_reserved[60];
    uint16_t e_lfanew;
};

struct PE_HEADER {
    uint32_t signature;
    uint16_t machine;      
    uint16_t numberOfSections;
    uint32_t timeDateStamp;
    uint32_t pointerToSymbolTable;
    uint32_t numberOfSymbols;
    uint16_t sizeOfOptionalHeader;
    uint16_t characteristics;
};

struct OPTIONAL_HEADER {
    uint16_t magic;      
    uint8_t  majorLinkerVersion;
    uint8_t  minorLinkerVersion;
    uint32_t sizeOfCode;
    uint32_t sizeOfInitializedData;
    uint32_t sizeOfUninitializedData;
    uint32_t addressOfEntryPoint;
    uint32_t baseOfCode;
};

struct SECTION_HEADER {
    char     name[8];
    uint32_t virtualSize;
    uint32_t virtualAddress;
    uint32_t sizeOfRawData;
    uint32_t pointerToRawData;
    uint32_t pointerToRelocations;
    uint32_t pointerToLinenumbers;
    uint16_t numberOfRelocations;
    uint16_t numberOfLinenumbers;
    uint32_t characteristics;
};

const uint32_t IMAGE_SCN_CNT_CODE = 0x00000020;
const uint32_t IMAGE_SCN_CNT_INITIALIZED_DATA = 0x00000040;
const uint32_t IMAGE_SCN_MEM_EXECUTE = 0x20000000;
const uint32_t IMAGE_SCN_MEM_READ = 0x40000000;
const uint32_t IMAGE_SCN_MEM_WRITE = 0x80000000;

struct PEAnalysisResult {
    bool isPE;
    bool is64bit;
    bool hasSuspiciousSections;
    bool hasWritableCodeSection;
    bool hasExecutableDataSection;
    int suspicionScore;
    std::vector<std::string> warnings;
};

bool isPEFile(const std::string& filepath);
PEAnalysisResult analyzePEFile(const std::string& filepath);
void printPEInfo(const std::string& filepath);

#endif