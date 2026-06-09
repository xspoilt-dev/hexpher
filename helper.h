#pragma once
#include <fstream>
#include <vector>
#include <string>
#include <cstring>
#include <cstdint>
#include <algorithm>
#include <elf.h>          // glibc ELF types — always available on Linux
#include "transmitter.h"

/* Sentinel for "not found / invalid" addresses */
constexpr uintptr_t OUT_OF_BOUNDS = 0xFFFFFFFFFFFFFFFFULL;

/* Raw file content */
struct f_content
{
    char*  buffer = nullptr;
    size_t size   = 0;
    bool   ok     = false;
};

/* Unified section descriptor (replaces pe_section) */
struct elf_section
{
    std::string  name;
    uint64_t     virtual_address;  // sh_addr
    uint64_t     raw_address;      // sh_offset  (file offset)
    uint64_t     raw_size;         // sh_size
};

/* Keep the old alias so the rest of the code compiles unchanged */
using pe_section = elf_section;

/* ---- generic helpers -------------------------------------------- */

template <typename T>
bool contains_element(std::vector<T>* vec, T item)
{
    return std::find(vec->begin(), vec->end(), item) != vec->end();
}

bool string_contains(std::string& haystack, const std::string& needle);

std::vector<std::string> split_string(std::string content, std::string delimiter);

std::vector<std::string> get_raw_bytes(std::string& byte_string);

bool is_register(std::string& value);

std::string string_to_hex(const std::string& input);

std::string duplicate_string(std::string text, uint32_t times);

/* ---- file / ELF helpers ----------------------------------------- */

f_content get_file_content(const std::string& filename);

/* Parse all ELF sections from the binary */
std::vector<elf_section> find_elf_sections(const std::string& filename);

/* Alias kept for compatibility with existing call-sites in main.cpp */
inline std::vector<elf_section> find_pe_sections(const std::string& filename)
{
    return find_elf_sections(filename);
}

/* ---- function-label helpers (used by transmitter) --------------- */

void label_all_functions(
    std::vector<Function>* functions,
    std::vector<std::string>* names
);

std::string find_last_function(std::vector<std::string>* names);

std::string find_function_name_by_addr(
    std::vector<Function>* functions,
    uint64_t               va
);