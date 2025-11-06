#include <stdio.h>
#include "MachOParser.h"
#include <mach-o/loader.h>
#include <mach-o/fat.h>

/*
 QUESTIONS:
 - should I declare magic numbers as macros?
 
 
 TO EXPLAIN:
 FILE *fp = fopen(...)
 typedef enum ...
 
 */


MachOError macho_parse_file(const char *filePath, MachOInfo *info) {
    FILE *fp = fopen(filePath, "rb");
    if (fp == NULL) {
        perror("fopen failed");
        return MACHO_ERROR_INVALID_FILE;
    }
    
    uint32_t magicBytes;
    
    size_t bytesRead = fread(&magicBytes, sizeof(uint32_t), 1, fp);
    if (bytesRead != sizeof(magicBytes)) {
        perror("error reading magic bytes");
        return MACHO_ERROR_READ_FAILED;
    }
    
    if (magicBytes == MH_MAGIC_64) {
        info->type = MACHO_TYPE_64BIT;
    } else if (magicBytes == MH_CIGAM_64) {
        info->type = MACHO_TYPE64BIT;
    } else if (magicBytes == MH_MAGIC) {
        info->type = MACHO_TYPE_BIT;
    } else if (magicBytes == FAT_MAGIC) {
        info->type = MACHO_TYPE_FAT;
    } else {
        perror("Not a Mach-O file (magic number: 0x%x)\n", magicBytes);
        fclose(fp);
        return MACHO_ERROR_INVALID_FILE;
    }
    
    fseek(fp, 0, SEEK_SET);
    
    // TODO: handle case 32 bit
    if (info->type == MACHO_TYPE_64BIT) {
        struct mach_header_64 header;
        fread(&header, sizeof(struct mach_header_64), 1, fp);
    } else {
        struct mach_header header;
        fread(&header, sizeof(struct mach_header), 1, fp);
    }
    info->cpu_type = header.cputype;
    info->cpu_subtype = header.cpusubtype;
    info->ncmds = header.ncmds;
    info->sizeofcmds = header.sizeofcmds;
    info->flags = header.flags;
    // TODO: missing SecurityFeatures and arch_name
    info->arch_name = macho_arch_name(info->cpu_type, info->cpu_subtype)
    
    if (info->flags & MH_PIE) {
        info->security.has_pie = true;
    } else {
        info->security.has_pie = false;
    }
    
    
    fclose(fp);
    
    return MACHO_SUCCESS;
}

const char *macho_arch_name(cpu_type_t cpu_type, cpu_subtype_t cpu_subtype) {
    
}

