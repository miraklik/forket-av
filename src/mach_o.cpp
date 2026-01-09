#include "mach_o.hpp"
#include <stdio.h>
#include <fstream>
#include <vector>
#include <mach-o/loader.h> 
#include <sys/stat.h>      

bool analyzeMachO(const std::string& filepath) {
    std::ifstream file(filepath, std::ios::binary | std::ios::ate);
    
    if (!file.is_open()) {
        printf("Failed to open file: %s\n", filepath.c_str());
        return false;
    }
    std::streamsize size = file.tellg();
    file.seekg(0, std::ios::beg);

    if (size < sizeof(mach_header_64)) {
        printf("File is too small to be a Mach-O file\n");
        return false;
    }

    std::vector<char> buffer(size);
    if (!file.read(buffer.data(), size)) {
        printf("Error: Failed to read file data.");
        return false;
    }
    auto* header = reinterpret_cast<mach_header_64*>(buffer.data());

    if (header->magic != MH_MAGIC_64) {
        printf("File is not a Mach-O file\n");
        return false;
    }

    printf("[INFO] Analyzing Mach-O Header: %s\n", filepath.c_str());

    uint8_t* commandPtr = reinterpret_cast<uint8_t*>(buffer.data()) + sizeof(mach_header_64);

    for (uint32_t i = 0; i < header->ncmds; ++i) {
        if (commandPtr >= reinterpret_cast<uint8_t*>(buffer.data()) + size) {
            break;
        }

        auto* command = reinterpret_cast<load_command*>(commandPtr);
        if (command->cmd == LC_SEGMENT_64) {
            auto* segment = reinterpret_cast<segment_command_64*>(command);
            int protections = segment->initprot;
            bool isWrite = (protections & VM_PROT_WRITE);
            bool isExec  = (protections & VM_PROT_EXECUTE);

            if (isWrite && isExec) {
                printf("[WARNING][DANGER] RWX Segment detected!");
                printf("File: %s\n", filepath.c_str());
                printf("Section Name: %s\n", segment->segname);
                return true;
            }
        }
        commandPtr += command->cmdsize;
    }

    return false; 
}