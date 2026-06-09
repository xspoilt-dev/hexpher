#pragma once

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// Disassemble one x86-64 instruction.
// bytes    - pointer to raw bytes
// max      - max bytes available
// offset   - virtual address of this instruction (for RIP-relative resolution)
// output   - buffer to write disassembly string (at least 256 bytes)
// resolved_addr - if the instruction is a LEA/CALL with RIP-relative addressing,
//                 the resolved absolute VA is written here; otherwise 0.
// Returns the number of bytes consumed (instruction length), or 1 on error.
unsigned int disassemble(
    unsigned char* bytes,
    unsigned int   max,
    uint64_t       offset,
    char*          output,
    uint64_t*      resolved_addr
);

#ifdef __cplusplus
}
#endif