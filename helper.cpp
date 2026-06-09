#include "helper.h"
#include "transmitter.h"
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <elf.h>

/* ------------------------------------------------------------------ */
/*  Basic string utilities                                              */
/* ------------------------------------------------------------------ */

bool string_contains(std::string& haystack, const std::string& needle)
{
    return haystack.find(needle) != std::string::npos;
}

std::vector<std::string> split_string(std::string content, std::string delimiter)
{
    size_t pos_start = 0, pos_end;
    size_t delim_len = delimiter.length();
    std::vector<std::string> res;

    while ((pos_end = content.find(delimiter, pos_start)) != std::string::npos)
    {
        res.push_back(content.substr(pos_start, pos_end - pos_start));
        pos_start = pos_end + delim_len;
    }
    res.push_back(content.substr(pos_start));
    return res;
}

std::vector<std::string> get_raw_bytes(std::string& byte_string)
{
    /* strip "ffffff" sign-extension artifacts */
    while (string_contains(byte_string, "ffffff"))
        byte_string.replace(byte_string.find("ffffff"), 6, "");

    std::vector<std::string> raw_bytes = split_string(byte_string, " ");
    raw_bytes.erase(
        std::remove_if(raw_bytes.begin(), raw_bytes.end(),
                       [](const std::string& x){ return x.empty(); }),
        raw_bytes.end());
    return raw_bytes;
}

/*
 * In x86-64, register names start with:
 *   'r'  — 64-bit GPRs (rax, rbx, rcx, rdx, rsi, rdi, rsp, rbp, r8..r15)
 *   'e'  — 32-bit GPRs (eax, ebx, …)
 *   'x','y','z' — SIMD regs (xmm, ymm, zmm)
 */
bool is_register(std::string& value)
{
    if (value.empty()) return false;
    char c = value[0];
    return (c == 'r' || c == 'e' || c == 'x' || c == 'y' || c == 'z');
}

std::string string_to_hex(const std::string& input)
{
    static const char hex_digits[] = "0123456789ABCDEF";
    std::string output;
    output.reserve(input.length() * 2);
    for (unsigned char c : input)
    {
        output.push_back(hex_digits[c >> 4]);
        output.push_back(hex_digits[c & 15]);
    }
    return output;
}

std::string duplicate_string(std::string text, uint32_t times)
{
    std::string result;
    for (uint32_t i = 0; i < times; i++)
        result += text;
    return result;
}

/* ------------------------------------------------------------------ */
/*  File I/O                                                            */
/* ------------------------------------------------------------------ */

f_content get_file_content(const std::string& filename)
{
    f_content fc;

    FILE* file = fopen(filename.c_str(), "rb");
    if (!file) return fc;

    fseek(file, 0L, SEEK_END);
    long numbytes = ftell(file);
    fseek(file, 0L, SEEK_SET);

    if (numbytes <= 0) { fclose(file); return fc; }

    char* bytes = (char*)calloc((size_t)numbytes, sizeof(char));
    if (!bytes)        { fclose(file); return fc; }

    fread(bytes, sizeof(char), (size_t)numbytes, file);
    fclose(file);

    fc.buffer = bytes;
    fc.size   = (size_t)numbytes;
    fc.ok     = true;
    return fc;
}

/* ------------------------------------------------------------------ */
/*  ELF section parser (replaces find_pe_sections)                     */
/* ------------------------------------------------------------------ */

std::vector<elf_section> find_elf_sections(const std::string& filename)
{
    std::vector<elf_section> sections;

    FILE* f = fopen(filename.c_str(), "rb");
    if (!f) return sections;

    /* Read ELF header */
    Elf64_Ehdr ehdr;
    if (fread(&ehdr, sizeof(ehdr), 1, f) != 1)
    {
        fclose(f); return sections;
    }

    /* Validate ELF magic */
    if (memcmp(ehdr.e_ident, ELFMAG, SELFMAG) != 0 || ehdr.e_ident[EI_CLASS] != ELFCLASS64)
    {
        fclose(f); return sections;
    }

    /* Read section header table */
    std::vector<Elf64_Shdr> shdrs(ehdr.e_shnum);
    fseek(f, (long)ehdr.e_shoff, SEEK_SET);
    fread(shdrs.data(), sizeof(Elf64_Shdr), ehdr.e_shnum, f);

    /* Read section-name string table */
    if (ehdr.e_shstrndx == SHN_UNDEF || ehdr.e_shstrndx >= ehdr.e_shnum)
    {
        fclose(f); return sections;
    }
    Elf64_Shdr& shstrtab_hdr = shdrs[ehdr.e_shstrndx];
    std::vector<char> shstrtab(shstrtab_hdr.sh_size + 1, '\0');
    fseek(f, (long)shstrtab_hdr.sh_offset, SEEK_SET);
    fread(shstrtab.data(), 1, shstrtab_hdr.sh_size, f);

    for (auto& shdr : shdrs)
    {
        std::string name = (shdr.sh_name < shstrtab.size())
                           ? std::string(&shstrtab[shdr.sh_name])
                           : std::string("");
        elf_section sec;
        sec.name            = name;
        sec.virtual_address = shdr.sh_addr;
        sec.raw_address     = shdr.sh_offset;
        sec.raw_size        = shdr.sh_size;
        sections.push_back(sec);
    }

    fclose(f);
    return sections;
}

/* ------------------------------------------------------------------ */
/*  label_all_functions                                                 */
/*  Maps ordered name list → Function structs (same logic as before)   */
/* ------------------------------------------------------------------ */

void label_all_functions(
    std::vector<Function>* functions,
    std::vector<std::string>* names)
{
    if (functions->empty() || names->empty()) return;

    uint32_t func_it = (uint32_t)functions->size() - 1;
    std::vector<std::string> r_names = *names;
    std::reverse(r_names.begin(), r_names.end());

    for (auto const& name : r_names)
    {
        if (func_it == (uint32_t)-1) break;
        (*functions)[func_it].function_name = name;
        /* Mark as main-package if the name has the "main." prefix */
        if (name.find("main.") != std::string::npos &&
            name.find("runtime.main") == std::string::npos)
        {
            (*functions)[func_it].from_main_pkg = true;
        }
        func_it--;
    }
}

std::string find_last_function(std::vector<std::string>* names)
{
    std::vector<std::string> reversed = *names;
    std::reverse(reversed.begin(), reversed.end());
    for (auto const& name : reversed)
    {
        if (name.rfind("type..eq.", 0) != std::string::npos ||
            name.rfind("main.",     0) != std::string::npos)
        {
            return name;
        }
    }
    return {};
}

std::string find_function_name_by_addr(
    std::vector<Function>* functions,
    uint64_t               va)
{
    for (auto const& func : *functions)
    {
        if (func.start_addr == va)
            return func.function_name;
    }
    /* fallback */
    char buf[64];
    snprintf(buf, sizeof(buf), "gofunc_0x%lx", (unsigned long)va);
    return std::string(buf);
}
