//
//  main.swift
//  MacHound
//
//  Created by 0xWasp on 10/28/25.
//

import Foundation
//import "MachOParser.h"

// Entry point for MacHound
print("🐕 MacHound - macOS Security Assessment Tool")
print(String(repeating: "=", count: 50))

// command line arguments
let arguments = CommandLine.arguments
guard arguments.count > 1 else {
    print("\nUsage: machound <binary-path>")
    print("\nExamples:")
    print("  machound /usr/bin/true")
    print("  machound /bin/ls")
    print("  machound /Applications/Safari.app/Contents/MacOS/Safari")
    exit(1)
}

let filepath = arguments[1]
print("\n Analyzing: \(filepath)")
//var filepath = "/bin/ls"
//var filepath = "/Users/0xwasp/Documents/01_Education/Programming/Swift/simple"
var info = MachOInfo()

var machoStatus = macho_parse_file(filepath, &info)

if machoStatus == MACHO_SUCCESS {
    print("\n✓ Successfully parsed Mach-O binary")
    macho_print_info(&info);
} else {
    print("\n✗ Failed to parse binary")
    print("Error code: \(machoStatus)")
    exit(1)
}
