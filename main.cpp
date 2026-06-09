#include <fstream>
#include <iostream>
#include <unordered_map>
#include <boost/format.hpp>
#include <vector>
#include <algorithm>
#include <elf.h>
#include "ansi.h"
#include "helper.h"
#include "transmitter.h"
#include "gui.hpp"

int main(int argc, char** argv)
{
    GUI gui;
    gui.configure_console();

    if (argc < 2 || argc > 3)
    {
        std::cout << gui.purple_plus
                  << " usage: hexpher <go_elf_binary> [compress: 0|1]\n";
        return -1;
    }

    bool arg_compress = (argc == 3 && std::string(argv[2]) == "1");

    /* ---- Load binary ---- */
    f_content fc = get_file_content(argv[1]);
    if (!fc.ok || !fc.buffer)
    {
        std::cout << gui.purple_plus << " error: could not read file.\n";
        return -1;
    }

    /* ---- Validate ELF 64-bit ---- */
    if (fc.size < sizeof(Elf64_Ehdr) ||
        memcmp(fc.buffer, ELFMAG, SELFMAG) != 0 ||
        (unsigned char)fc.buffer[EI_CLASS] != ELFCLASS64)
    {
        std::cout << gui.purple_plus
                  << " error: file is not a 64-bit ELF binary.\n";
        return -1;
    }

    /* ---- Parse ELF sections ---- */
    std::vector<elf_section> sections = find_elf_sections(argv[1]);

    auto find_sec = [&](const std::string& name) -> elf_section* {
        for (auto& s : sections)
            if (s.name == name) return &s;
        return nullptr;
    };

    elf_section* rodata_sec = find_sec(".rodata");
    elf_section* text_sec   = find_sec(".text");

    if (!text_sec)
    {
        std::cout << gui.purple_plus << " error: no .text section found.\n";
        return -1;
    }

    uint64_t rodata_va  = rodata_sec ? rodata_sec->virtual_address : 0;
    uint64_t rodata_off = rodata_sec ? rodata_sec->raw_address      : 0;
    uint64_t rodata_sz  = rodata_sec ? rodata_sec->raw_size         : 0;

    /* ---- Extract function names from ELF symtab ---- */
    std::vector<std::string> names = get_function_names(fc.buffer, fc.size);

    if (names.empty())
    {
        std::cout << gui.purple_plus
                  << " warning: no symbols found. Binary may be stripped.\n"
                  << " tip: compile with: go build -ldflags=\"-s=false -w=false\"\n";
    }

    /* ---- Disassemble all Go functions ---- */
    std::vector<Function> funcs = get_all_go_functions(fc.buffer, fc.size, argv[1]);

    std::cout << gui.cyan_plus
              << " Found " << funcs.size()
              << " functions in this Go binary!\n\n";

    /* ---- Print main-package functions ---- */
    std::vector<std::string> main_funcs = get_main_defined_functions(names);
    std::cout << "[" << Colors[Cyan] << "main pkg functions" << Colors[White] << "]\n";
    for (auto const& f : main_funcs)
        std::cout << gui.cyan_plus << " " << Colors[Cyan] << f << Colors[White] << "()\n";
    std::cout << "\n";

    /* ---- Print imports ---- */
    std::vector<std::string> packages = get_all_imports(names);
    std::cout << "[" << Colors[Cyan] << "packages" << Colors[White] << "]\nimport (\n";
    for (auto const& pkg : packages)
        std::cout << "\t\"" << Colors[Cyan] << pkg << Colors[White] << "\"\n";
    std::cout << ")\n\n";

    /* ---- Print strings from main-package functions ---- */
    if (rodata_sec)
    {
        std::cout << "[" << Colors[Cyan] << "strings" << Colors[White] << "]\n";
        for (auto& fn : funcs)
        {
            if (!fn.from_main_pkg) continue;
            auto strs = get_strings_from_function(
                &fn, fc.buffer, fc.size, rodata_va, rodata_off);
            for (auto const& s : strs)
                std::cout << gui.cyan_plus
                          << " \"" << Colors[Cyan] << s << Colors[White] << "\"\n";
        }
        std::cout << "\n";
    }

    /* ---- Translate each main-package function → pseudo-code ---- */
    for (auto& fn : funcs)
    {
        if (!fn.from_main_pkg) continue;

        TMessage tmsg   = {};
        tmsg.function       = &fn;
        tmsg.all_functions  = &funcs;
        tmsg.buffer         = fc.buffer;
        tmsg.b_size         = fc.size;
        tmsg.rodata_va      = rodata_va;
        tmsg.rodata_offset  = rodata_off;
        tmsg.rodata_size    = rodata_sz;
        tmsg.text_va        = text_sec->virtual_address;
        tmsg.text_offset    = text_sec->raw_address;
        tmsg.compress       = arg_compress;
        tmsg.indent_level   = 1;

        std::string pseudo = translate_function(&tmsg);
        std::cout << pseudo << "\n";
    }

    free(fc.buffer);
    return 0;
}
