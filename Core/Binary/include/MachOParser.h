//
//  MachOParser.h
//  MacHound
//
//  Created by 0xWasp on 10/28/25.
//

#ifndef MachOParser_h
#define MachOParser_h

// Header files explained:
// <stdint.h>    - Provides fixed-width integer types (uint32_t, uint64_t, etc.)
// <stdbool.h>   - Provides bool type and true/false constants
// <mach/machine.h> - Provides CPU type constants (cpu_type_t, cpu_subtype_t)
#include <stdint.h>
#include <stdbool.h>
#include <mach/machine.h>

#define MAX_LOAD_COMMANDS 256

// important Load Commands types
typedef enum {
    LC_TYPE_SEGMENT = 0,
    LC_TYPE_DYLIB,
    LC_TYPE_CODE_SIGNATURE,
    LC_TYPE_MAIN,
    LC_TYPE_UNKOWN
} LoadCommandType;

// Simplified Load Command info
typedef struct {
    LoadCommandType type;
    uint32_t cmd;           // Original command value
    uint32_t cmdsize;       // Size of command
    char name[256];         // For dylib names, segment names
    uint64_t vmaddr;        // For segments
    uint64_t vmsize;        // For segments
    uint32_t fileoff;       // For code signature
    uint32_t filesize;      // For code signature
} LoadCommandInfo;

// error codes
typedef enum {
    MACHO_SUCCESS = 0,
    MACHO_ERROR_INVALID_FILE = -1,
    MACHO_ERROR_NOT_MACHO = -2,
    MACHO_ERROR_UNSUPPORTED = -3,
    MACHO_ERROR_READ_FAILED = -4
} MachOError;

// file types
// In C enums, if you don't specify a value, it automatically gets the next integer
// Starting from 0: UNKNOWN=0, 32BIT=1, 64BIT=2, FAT=3, FAT64=4
typedef enum {
    MACHO_TYPE_UNKNOWN = 0,
    MACHO_TYPE_32BIT,
    MACHO_TYPE_64BIT,
    MACHO_TYPE_FAT,
    MACHO_TYPE_FAT64
} MachOType;

// security features flags
typedef struct {
    bool has_pie;           // Position Independent Executable
    bool has_stack_canary;  // Stack protection
    bool has_nx_heap;       // Non-executable heap
    bool has_nx_stack;      // Non-executable stack
    bool has_restrict;      // Restricted segment
    bool is_notarized;      // Apple notarization
} SecurityFeatures;

// main info structure
// Yes, this matches the MachOInfo struct defined in Phase1_Header_Guide.md
// This is the central data structure for storing parsed Mach-O information
typedef struct {
    MachOType type;
    cpu_type_t cpu_type;
    cpu_subtype_t cpu_subtype;
    uint32_t ncmds;
    uint32_t sizeofcmds;
    uint32_t flags;
    SecurityFeatures security;
    char arch_name[32];
    
    // Load Commands
    LoadCommandInfo load_commands[MAX_LOAD_COMMANDS];
    uint32_t num_load_commands_parsed;
    
    // Extracted info
    char dylibs[32][256]; // Up to 32 dylib dependencies TODO: why only 32?
    uint32_t num_dylibs;
    uint64_t entry_point; // main entry point
    bool has_code_signature;
} MachOInfo;

/**
 Parse Load Commands
 @param fp Pointer to a file
 @param info Pointer to MachOInfo struct
 @return MachOError status 
 */
MachOError macho_parse_load_commands(FILE *fp, MachOInfo *info);

/**
 * Parse a Mach-O binary file
 * @param filepath Path to the binary
 * @param info Pointer to MachOInfo structure to fill
 * @return MACHO_SUCCESS or error code
 */
MachOError macho_parse_file(const char *filepath, MachOInfo *info);


/**
 * Get human-readable error message
 * @param error Error code from macho_parse_file
 * @return Error description string
 */
const char *macho_error_string(MachOError error);


/**
 * Get architecture name from CPU type
 * @param cpu_type CPU type constant
 * @return Architecture string (e.g., "arm64", "x86_64")
 */
const char *macho_arch_name(cpu_type_t cpu_type);


/**
 * Check if file is a valid Mach-O binary
 * @param filepath Path to check
 * @return true if valid Mach-O, false otherwise
 */
bool macho_is_valid(const char *filepath);


/**
 * Print detailed information about a Mach-O file
 * @param info Parsed MachOInfo structure
 */
void macho_print_info(const MachOInfo *info);


//#ifdef MACHO_PARSER_ADVANCED

/**
 * Extract load commands from binary
 * @param filepath Path to binary
 * @param commands Array to fill with commands
 * @param max_commands Size of array
 * @return Number of commands extracted
 */
int mach_extract_load_commands(const char *filepath, void *commands, int max_commands);


/**
 * Get entitlements from code signature
 * @param filepath Path to binary
 * @return Entitlements XML string (caller must free)
 */
char *macho_get_entitlements(const char *filepath);



#endif /* MachOParser_h */
