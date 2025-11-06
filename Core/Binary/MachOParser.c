#include <stdio.h>
#include "MachOParser.h"
#include <mach-o/loader.h>
#include <mach-o/fat.h>
#include <string.h>

/*
 QUESTIONS:
 
 
 TO EXPLAIN:
 typedef enum ...
 
 */

/**
 * Get architecture name from CPU type
 * @param cpu_type CPU type constant
 * @return Architecture string (e.g., "arm64", "x86_64")
 */
const char *macho_arch_name(cpu_type_t cpu_type) {
    switch(cpu_type) {
        case CPU_TYPE_ARM64:
            return "arm64";
        case CPU_TYPE_ARM:
            return "arm";
        case CPU_TYPE_X86_64:
            return "x86_64";
        case CPU_TYPE_X86:
            return "x86";
        case CPU_TYPE_POWERPC:
            return "powerpc";
        case CPU_TYPE_POWERPC64:
            return "powerpc64";
        default:
            return "unknown";
    }
}


/**
 * Get human-readable error message
 * @param error Error code from macho_parse_file
 * @return Error description string
 */
//const char *macho_error_string(MachOError error);



/**
 * Check if file is a valid Mach-O binary
 * @param filePath Path to check
 * @return true if valid Mach-O, false otherwise
 */
//bool macho_is_valid(const char *filePath){
//    FILE *fp = fopen(filePath, "rb");
//    if (fp == NULL) {
//        perror("fopen failed");
//        return MACHO_ERROR_INVALID_FILE;
//    }
//    
//    uint32_t magicBytes;
//    
//    size_t itemsRead = fread(&magicBytes, sizeof(uint32_t), 1, fp);
//    if (itemsRead != 1) {
//        perror("error reading magic bytes");
//        return MACHO_ERROR_READ_FAILED;
//    }
//    
//    if (magicBytes == MH_MAGIC_64 || magicBytes == MH_CIGAM_64 || magicBytes == MH_MAGIC || magicBytes == MH_MAGIC_64 ) {
//        fclose(fp);
//        return true;
//    } else if (magicBytes == FAT_MAGIC || magicBytes == FAT_MAGIC_64 || magicBytes == FAT_CIGAM | magicBytes == FAT_CIGAM_64){
//        printf("Fat binary detected - not yet supported\n");
//        fclose(fp);
//        return MACHO_ERROR_UNSUPPORTED;
//    }
//    else {
//        fprintf(stderr, "Not a Mach-O file (magic number: 0x%x).\n", magicBytes);
//        fclose(fp);
//        return false;
//    }
//}


/**
 * Print detailed information about a Mach-O file
 * @param info Parsed MachOInfo structure
 */
void macho_print_info(const MachOInfo *info){
    printf("\n╔════════════════════════════════════════╗\n");
    printf("║      Mach-O Binary Analysis            ║\n");
    printf("╚════════════════════════════════════════╝\n");

    printf("\n Binary Information:\n");
    printf("  Type: %s\n",
           info->type == MACHO_TYPE_64BIT ? "64-bit Mach-O" :
           info->type == MACHO_TYPE_32BIT ? "32-bit Mach-O" : "Unknown");
    printf("    Architecture: %s\n", info->arch_name);
    printf("    CPU Type: 0x%x\n", info->cpu_type); // FIXME: fix how the arch number is displayed
    printf("    Number of Load Commands: %u\n", info->ncmds);
    printf("    Load Commands Size: %u bytes\n", info->sizeofcmds);
    
    printf("\n Security Features:\n");
    printf("  [%s] PIE (Position Independent)\n", info->security.has_pie ? "✓" : "✗");
    printf("  [%s] NX Heap (Non-executable heap)\n", info->security.has_nx_heap ? "✓" : "✗");
    printf("  [%s] NX Stack (Non-executable stack)\n", info->security.has_nx_stack ? "✓" : "✗");
}


MachOError macho_parse_load_commands(FILE *fp, MachOInfo *info) {
    // initialization
    info->num_load_commands_parsed = 0;
    info->num_dylibs = 0;
    info->entry_point = 0;
    info->has_code_signature = false;
    
    // We're positioned right after the header
    // (macho_parse_file already read header)
    uint32_t offset = (info->type == MACHO_TYPE_64BIT) ? sizeof(struct mach_header_64) : sizeof(struct mach_header);
    
    fseek(fp, offset, SEEK_SET);
    
    // iterate through each Load Command
    for (uint32_t i = 0; i < info->ncmds && i < MAX_LOAD_COMMANDS; i++) {
        struct load_command lc;
        
        size_t read = fread(&lc, sizeof(struct load_command), 1, fp);
        if (read != 1){
            fprintf(stderr, "Failed to read Load Command %u\n", i);
            return MACHO_ERROR_READ_FAILED;
        }
        
        info->load_commands[i].cmd = lc.cmd;
        info->load_commands[i].cmdsize = lc.cmdsize;
        
        // TODO: parse specific command types
        switch (lc.cmd){
            case LC_SEGMENT_64: {
                
            }
        }
        
        // move to the next LC
        uint32_t remaining = lc.cmdsize - sizeof(struct load_command);
        fseek(fp, remaining, SEEK_CUR);
        
        info->num_load_commands_parsed++;
        
    }
    
    printf("Parsed %u Load Commands\n", info->num_load_commands_parsed);
        
    return MACHO_SUCCESS;
}


MachOError macho_parse_file(const char *filePath, MachOInfo *info) {
    FILE *fp = fopen(filePath, "rb");
    if (fp == NULL) {
        perror("fopen failed");
        return MACHO_ERROR_INVALID_FILE;
    }
    
    uint32_t magicBytes;
    
    size_t itemsRead = fread(&magicBytes, sizeof(uint32_t), 1, fp);
    if (itemsRead != 1) {
        perror("error reading magic bytes");
        return MACHO_ERROR_READ_FAILED;
    }
    
    if (magicBytes == MH_MAGIC_64) {
        info->type = MACHO_TYPE_64BIT;
    } else if (magicBytes == MH_CIGAM_64) {
        info->type = MACHO_TYPE_64BIT;
    } else if (magicBytes == MH_MAGIC) {
        info->type = MACHO_TYPE_32BIT;
    } else if (magicBytes == FAT_MAGIC) {
        info->type = MACHO_TYPE_FAT;
    } else {
        fprintf(stderr, "Not a Mach-O file (magic number: 0x%x).\n", magicBytes);
        fclose(fp);
        return MACHO_ERROR_NOT_MACHO;
    }
//    bool machoIsValid = macho_is_valid(filePath);
//    if (!machoIsValid) {
//        perror("This is not a Mach-O file.");
//        return MACHO_ERROR_UNSUPPORTED;
//    }
    
    fseek(fp, 0, SEEK_SET);
    
    if (info->type == MACHO_TYPE_64BIT) {
        struct mach_header_64 header;
        fread(&header, sizeof(struct mach_header_64), 1, fp);
        info->cpu_type = header.cputype;
        info->cpu_subtype = header.cpusubtype;
        info->ncmds = header.ncmds;
        info->sizeofcmds = header.sizeofcmds;
        info->flags = header.flags;
        strncpy(info->arch_name, macho_arch_name(info->cpu_type), sizeof(info->arch_name) - 1);
        info->arch_name[31] = '\0';
        // Initialize all security features to false
          info->security.has_pie = false;
          info->security.has_stack_canary = false;
          info->security.has_nx_heap = false;
          info->security.has_nx_stack = false;
          info->security.has_restrict = false;
          info->security.is_notarized = false;
        
//        info->security = {false};
        if (header.flags & MH_PIE) {
            info->security.has_pie = true;
        }
        if (header.flags & MH_NO_HEAP_EXECUTION) {
            info->security.has_nx_heap = true;
        }
        if (!(header.flags & MH_ALLOW_STACK_EXECUTION)) {
            info->security.has_nx_stack = true;
        }
    } else if (info->type == MACHO_TYPE_32BIT) {
        struct mach_header header;
        fread(&header, sizeof(struct mach_header), 1, fp);
        info->cpu_type = header.cputype;
        info->cpu_subtype = header.cpusubtype;
        info->ncmds = header.ncmds;
        info->sizeofcmds = header.sizeofcmds;
        info->flags = header.flags;
        strncpy(info->arch_name, macho_arch_name(info->cpu_type), sizeof(info->arch_name) - 1);
        info->arch_name[31] = '\0';
        // Initialize all security features to false
          info->security.has_pie = false;
          info->security.has_stack_canary = false;
          info->security.has_nx_heap = false;
          info->security.has_nx_stack = false;
          info->security.has_restrict = false;
          info->security.is_notarized = false;
        
//        info->security = {false};
        if (header.flags & MH_PIE) {
            info->security.has_pie = true;
        }
        if (header.flags & MH_NO_HEAP_EXECUTION) {
            info->security.has_nx_heap = true;
        }
        if (!(header.flags & MH_ALLOW_STACK_EXECUTION)) {
            info->security.has_nx_stack = true;
        }
    } else {
        fprintf(stderr, "This file type in not supported: %s\n",  macho_arch_name(info->cpu_type));
        return MACHO_ERROR_UNSUPPORTED;
    }
    
    fclose(fp);
    
    return MACHO_SUCCESS;
}



