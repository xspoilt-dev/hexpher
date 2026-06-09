#include "transmitter.h"
#include "helper.h"
#include <cstdio>
#include <cstring>
#include <elf.h>

/* ------------------------------------------------------------------ */
/* Helpers                                                              */
/* ------------------------------------------------------------------ */

Instruction get_instruction_used(std::string& raw_asm)
{
    std::string mnem = split_string(raw_asm, " ")[0];
    auto it = instructions_map.find(mnem);
    return (it != instructions_map.end()) ? it->second : Instruction::UNDEFINED;
}

std::string find_function_name(std::vector<Function>* functions, uint64_t va)
{
    for (auto const& f : *functions)
        if (f.start_addr == va) return f.function_name;
    char buf[64];
    snprintf(buf, sizeof(buf), "gofunc_0x%lx", (unsigned long)va);
    return std::string(buf);
}

/* Convert a rodata virtual-address to a file offset into `buffer` */
static inline bool va_to_buf(uint64_t va, char* buffer, size_t bsize,
                              uint64_t rodata_va, uint64_t rodata_off,
                              uint64_t rodata_size, const char** out)
{
    if (va < rodata_va || va >= rodata_va + rodata_size) return false;
    uint64_t off = rodata_off + (va - rodata_va);
    if (off >= bsize) return false;
    *out = buffer + off;
    return true;
}

/* ------------------------------------------------------------------ */
/* translate_function  — emit Go-like pseudo-code for one function      */
/* ------------------------------------------------------------------ */
std::string translate_function(TMessage* tmsg)
{
    std::vector<uint32_t> instructions_used;
    tmsg->instructions_used = &instructions_used;

    std::string        pcode;
    std::queue<std::string> stack;
    uint32_t sc = 0, ic = 0, bc = 0, vc = 0;

    pcode += (boost::format("func %1%()\n{\n") % tmsg->function->function_name).str();

    for (size_t i = 4; i < tmsg->function->ibuffers.size(); i++)
    {
        if (contains_element(&instructions_used, (uint32_t)i)) continue;

        auto& ib  = tmsg->function->ibuffers[i];
        auto& ibn = (i + 1 < tmsg->function->ibuffers.size())
                    ? tmsg->function->ibuffers[i+1]
                    : tmsg->function->ibuffers[i];

        std::string tabs = duplicate_string(tab_string, tmsg->indent_level);

        /* ---- CALL ---- */
        if (ib.instruction == CALL)
        {
            instructions_used.push_back((uint32_t)i);
            std::string fname = find_function_name(tmsg->all_functions, ib.resolved_addr);
            bool has_err = (i+1 < tmsg->function->ibuffers.size() &&
                            ibn.raw_asm.find("mov") != std::string::npos &&
                            i >= 2 && tmsg->function->ibuffers[i-2].instruction == LEA);
            if (has_err) {
                instructions_used.push_back((uint32_t)(i+1));
                pcode += (boost::format("%1%data, err := %2%(") % tabs % fname).str();
            } else {
                pcode += (boost::format("%1%data := %2%(") % tabs % fname).str();
            }
            while (!stack.empty()) {
                pcode += (stack.size() == 1) ? stack.front() : stack.front() + ", ";
                stack.pop();
            }
            pcode += ")\n\n";
        }

        /* ---- LEA rX, [rip+offset]  →  string literal ---- */
        if (ib.instruction == LEA && ib.resolved_addr != 0 &&
            ib.raw_asm.find("rip") != std::string::npos &&
            i+2 < tmsg->function->ibuffers.size() &&
            tmsg->function->ibuffers[i+2].instruction == MOV)
        {
            instructions_used.push_back((uint32_t)i);
            /* Next MOV likely carries the string length */
            auto& len_ib = tmsg->function->ibuffers[i+2];
            std::string len_part = split_string(len_ib.raw_asm, ",").back();
            int slen = 0;
            if (!len_part.empty() && !is_register(len_part))
            {
                try { slen = std::stoi(len_part, nullptr, 16); } catch(...) {}
            }

            const char* sptr = nullptr;
            if (slen > 0 && va_to_buf(ib.resolved_addr, tmsg->buffer, tmsg->b_size,
                                       tmsg->rodata_va, tmsg->rodata_offset,
                                       tmsg->rodata_size, &sptr))
            {
                instructions_used.push_back((uint32_t)(i+1));
                instructions_used.push_back((uint32_t)(i+2));
                std::string s(sptr, (size_t)slen);
                if (!tmsg->compress) {
                    pcode += (boost::format("%1%string_%2% := \"%3%\"\n") % tabs % sc % s).str();
                    stack.push((boost::format("string_%1%") % sc).str());
                } else {
                    stack.push((boost::format("\"%1%\"") % s).str());
                }
                sc++;
            }
        }

        /* ---- TEST + JZ  →  error check ---- */
        if (ib.instruction == TEST && ibn.instruction == JZ)
        {
            instructions_used.push_back((uint32_t)i);
            instructions_used.push_back((uint32_t)(i+1));
            pcode += tabs + "if err != nil {\n" + tabs + "\tpanic(err)\n" + tabs + "}\n";
        }

        /* ---- MOV QWORD/DWORD  →  integer literal ---- */
        if (ib.raw_asm.find("mov qword ptr") != std::string::npos ||
            ib.raw_asm.find("mov dword ptr") != std::string::npos)
        {
            if (ib.raw_asm.find("rip") == std::string::npos &&
                (i == 0 || tmsg->function->ibuffers[i-1].instruction != LEA))
            {
                instructions_used.push_back((uint32_t)i);
                std::string val = split_string(ib.raw_asm, ",").back();
                if (!val.empty() && !is_register(val)) {
                    int64_t v = 0;
                    try { v = (int64_t)std::stoll(val, nullptr, 16); } catch(...) {}
                    if (!tmsg->compress) {
                        pcode += (boost::format("%1%integer_%2% := %3%\n") % tabs % ic % v).str();
                        stack.push((boost::format("integer_%1%") % ic).str());
                    } else {
                        stack.push(std::to_string(v));
                    }
                    ic++;
                }
            }
        }

        /* ---- MOV BYTE PTR  →  boolean ---- */
        if (ib.raw_asm.find("mov byte ptr") != std::string::npos)
        {
            instructions_used.push_back((uint32_t)i);
            std::string bval = split_string(ib.raw_asm, ",").back();
            int bv = 0;
            try { bv = std::stoi(bval, nullptr, 16); } catch(...) {}
            const char* bstr = (bv == 1) ? "true" : "false";
            if (!tmsg->compress) {
                pcode += (boost::format("%1%boolean_%2% := %3%\n") % tabs % bc % bstr).str();
                stack.push((boost::format("boolean_%1%") % bc).str());
            } else {
                stack.push(bstr);
            }
            bc++;
        }

        /* ---- ADD/SUB/IMUL/IDIV ---- */
        if (ib.instruction == ADD || ib.instruction == ADC)
        {
            if (ib.raw_asm.find("],") != std::string::npos) {
                std::string sv = split_string(ib.raw_asm, "],").back();
                uint64_t uv = 0;
                try { uv = std::stoull(sv, nullptr, 16); } catch(...) {}
                if (uv > (uint64_t)INT64_MAX)
                    pcode += (boost::format("%1%data = data - %2%\n") % tabs % -(int64_t)uv).str();
                else
                    pcode += (boost::format("%1%data = data + %2%\n") % tabs % uv).str();
            }
        }
        if (ib.instruction == IMUL) {
            std::string sv = split_string(ib.raw_asm, ",").back();
            uint64_t uv = 0;
            try { uv = std::stoull(sv, nullptr, 16); } catch(...) {}
            pcode += (boost::format("%1%data = data * %2%\n") % tabs % uv).str();
        }
        if (ib.instruction == IDIV) {
            std::string sv = split_string(ib.raw_asm, ",").back();
            uint64_t uv = 0;
            try { uv = std::stoull(sv, nullptr, 16); } catch(...) {}
            pcode += (boost::format("%1%data = data / %2%\n") % tabs % uv).str();
        }
    }
    pcode += "\n}\n";
    return pcode;
}

/* ------------------------------------------------------------------ */
/* translate_block  — emit code for a branch body                       */
/* ------------------------------------------------------------------ */
std::string translate_block(TMessage* tmsg)
{
    std::string pcode;
    for (size_t i = 0; i < tmsg->function->ibuffers.size(); i++)
    {
        auto& ib = tmsg->function->ibuffers[i];
        if (ib.address == tmsg->jmp_addr) { tmsg->indent_level--; break; }
        if (ib.instruction == JMP)        { tmsg->indent_level--; break; }
        if (ib.instruction == CALL) {
            std::string fname = find_function_name(tmsg->all_functions, ib.resolved_addr);
            pcode += duplicate_string(tab_string, tmsg->indent_level) +
                     "data := " + fname + "()\n";
        }
    }
    return pcode;
}

/* ------------------------------------------------------------------ */
/* get_function_names — read Go symbol names from ELF .symtab           */
/* ------------------------------------------------------------------ */
std::vector<std::string> get_function_names(char* buffer, size_t buff_size)
{
    std::vector<std::string> names;
    if (buff_size < sizeof(Elf64_Ehdr)) return names;

    auto* ehdr = reinterpret_cast<Elf64_Ehdr*>(buffer);
    if (memcmp(ehdr->e_ident, ELFMAG, SELFMAG) != 0) return names;

    auto* shdrs = reinterpret_cast<Elf64_Shdr*>(buffer + ehdr->e_shoff);
    if ((uint64_t)(ehdr->e_shoff + ehdr->e_shnum * sizeof(Elf64_Shdr)) > buff_size)
        return names;

    /* Find .symtab and its .strtab */
    Elf64_Shdr* symtab_sh  = nullptr;
    Elf64_Shdr* strtab_sh  = nullptr;
    for (int i = 0; i < ehdr->e_shnum; i++) {
        if (shdrs[i].sh_type == SHT_SYMTAB) {
            symtab_sh = &shdrs[i];
            if (shdrs[i].sh_link < (uint32_t)ehdr->e_shnum)
                strtab_sh = &shdrs[shdrs[i].sh_link];
            break;
        }
    }
    if (!symtab_sh || !strtab_sh) return names;

    uint64_t sym_end = symtab_sh->sh_offset + symtab_sh->sh_size;
    uint64_t str_end = strtab_sh->sh_offset + strtab_sh->sh_size;
    if (sym_end > buff_size || str_end > buff_size) return names;

    const char* strtab = buffer + strtab_sh->sh_offset;
    auto*       syms   = reinterpret_cast<Elf64_Sym*>(buffer + symtab_sh->sh_offset);
    size_t      nsyms  = symtab_sh->sh_size / sizeof(Elf64_Sym);

    for (size_t i = 0; i < nsyms; i++) {
        if (ELF64_ST_TYPE(syms[i].st_info) != STT_FUNC) continue;
        if (syms[i].st_name >= strtab_sh->sh_size)      continue;
        std::string nm = strtab + syms[i].st_name;
        if (nm.empty()) continue;
        names.push_back(nm);
    }
    return names;
}

/* ------------------------------------------------------------------ */
/* get_all_function_labels — same as get_function_names for ELF         */
/* ------------------------------------------------------------------ */
std::vector<std::string> get_all_function_labels(
    char* buffer, size_t buff_size, const std::string& /*last_func*/)
{
    return get_function_names(buffer, buff_size);
}

void fix_function_labels(std::vector<std::string>*, std::vector<std::string>*) {}

/* ------------------------------------------------------------------ */
/* get_all_go_functions — ELF symtab + Capstone disassembly             */
/* ------------------------------------------------------------------ */
std::vector<Function> get_all_go_functions(
    char* buffer, size_t buff_size, const std::string& /*filename*/)
{
    std::vector<Function> functions;
    if (buff_size < sizeof(Elf64_Ehdr)) return functions;

    auto* ehdr  = reinterpret_cast<Elf64_Ehdr*>(buffer);
    if (memcmp(ehdr->e_ident, ELFMAG, SELFMAG) != 0) return functions;

    auto* shdrs = reinterpret_cast<Elf64_Shdr*>(buffer + ehdr->e_shoff);

    Elf64_Shdr* symtab_sh  = nullptr;
    Elf64_Shdr* strtab_sh  = nullptr;
    Elf64_Shdr* text_sh    = nullptr;

    /* Locate .symtab, its strtab, and .text sections */
    Elf64_Shdr* shstrtab_sh = &shdrs[ehdr->e_shstrndx];
    const char* shstr = buffer + shstrtab_sh->sh_offset;

    for (int i = 0; i < ehdr->e_shnum; i++) {
        std::string sn = shstr + shdrs[i].sh_name;
        if (shdrs[i].sh_type == SHT_SYMTAB) {
            symtab_sh = &shdrs[i];
            if (shdrs[i].sh_link < (uint32_t)ehdr->e_shnum)
                strtab_sh = &shdrs[shdrs[i].sh_link];
        }
        if (sn == ".text") text_sh = &shdrs[i];
    }
    if (!symtab_sh || !strtab_sh || !text_sh) return functions;

    const char* strtab = buffer + strtab_sh->sh_offset;
    auto*       syms   = reinterpret_cast<Elf64_Sym*>(buffer + symtab_sh->sh_offset);
    size_t      nsyms  = symtab_sh->sh_size / sizeof(Elf64_Sym);

    auto t0 = std::chrono::high_resolution_clock::now();

    for (size_t si = 0; si < nsyms; si++)
    {
        if (ELF64_ST_TYPE(syms[si].st_info) != STT_FUNC) continue;
        if (syms[si].st_size == 0) continue;
        if (syms[si].st_name >= strtab_sh->sh_size) continue;

        std::string nm = strtab + syms[si].st_name;
        if (nm.empty()) continue;

        uint64_t va   = syms[si].st_value;
        uint64_t size = syms[si].st_size;

        /* Convert VA → file offset via .text section */
        if (va < text_sh->sh_addr || va >= text_sh->sh_addr + text_sh->sh_size) continue;
        uint64_t foff = text_sh->sh_offset + (va - text_sh->sh_addr);
        if (foff + size > buff_size) continue;

        /* Disassemble */
        std::vector<IBuffer> ibuffers;
        uint64_t cursor = foff;
        uint64_t va_cur = va;
        uint64_t end    = foff + size;

        while (cursor < end)
        {
            char     asm_buf[256] = {};
            uint64_t res_addr     = 0;
            unsigned consumed = disassemble(
                (unsigned char*)buffer + cursor,
                (unsigned)(end - cursor),
                va_cur, asm_buf, &res_addr);
            if (consumed == 0) consumed = 1;

            IBuffer ib;
            ib.address       = va_cur;
            ib.raw_asm       = asm_buf;
            ib.instruction   = get_instruction_used(ib.raw_asm);
            ib.resolved_addr = res_addr;

            /* Build raw-byte hex string */
            std::string bstr;
            for (unsigned b = 0; b < consumed; b++) {
                char hx[8];
                snprintf(hx, sizeof(hx), "%02x ", (unsigned char)buffer[cursor + b]);
                bstr += hx;
            }
            ib.raw_bytes = get_raw_bytes(bstr);

            ibuffers.push_back(ib);

            cursor += consumed;
            va_cur += consumed;

            if (ib.instruction == RET || ib.instruction == RETN) break;
        }

        Function fn;
        fn.start_addr    = va;
        fn.end_addr      = va + size;
        fn.function_name = nm;
        fn.ibuffers      = std::move(ibuffers);
        fn.from_main_pkg = (nm.find("main.") != std::string::npos &&
                            nm.find("runtime.main") == std::string::npos);
        functions.push_back(std::move(fn));
    }

    auto t1  = std::chrono::high_resolution_clock::now();
    auto dur = std::chrono::duration_cast<std::chrono::seconds>(t1 - t0);
    fprintf(stderr, "[+] Disassembled %zu functions in %ld seconds.\n",
            functions.size(), (long)dur.count());

    return functions;
}

/* ------------------------------------------------------------------ */
/* get_strings_from_function                                            */
/* ------------------------------------------------------------------ */
std::vector<std::string> get_strings_from_function(
    Function* function, char* buffer, size_t buffer_size,
    uint64_t rodata_va, uint64_t rodata_offset)
{
    std::vector<std::string> strings;

    /* Find rodata size from difference (approximation) */
    uint64_t rodata_size = buffer_size;

    for (size_t i = 4; i + 2 < function->ibuffers.size(); i++)
    {
        auto& ib = function->ibuffers[i];
        if (ib.instruction != LEA) continue;
        if (ib.raw_asm.find("rip") == std::string::npos) continue;
        if (ib.resolved_addr == 0) continue;
        if (function->ibuffers[i+2].instruction != MOV) continue;

        std::string len_part = split_string(function->ibuffers[i+2].raw_asm, ",").back();
        if (is_register(len_part)) continue;
        int slen = 0;
        try { slen = std::stoi(len_part, nullptr, 16); } catch(...) { continue; }
        if (slen <= 0 || slen > 4096) continue;

        const char* sptr = nullptr;
        if (!va_to_buf(ib.resolved_addr, buffer, buffer_size,
                       rodata_va, rodata_offset, rodata_size, &sptr)) continue;
        if ((uint64_t)((sptr - buffer) + slen) > buffer_size) continue;

        std::string s(sptr, (size_t)slen);
        /* Only keep printable strings */
        bool printable = true;
        for (char c : s)
            if ((unsigned char)c < 0x20 || (unsigned char)c > 0x7E) { printable = false; break; }
        if (!printable || s.empty()) continue;

        strings.push_back(s);
    }
    return strings;
}

/* ------------------------------------------------------------------ */
/* get_main_defined_functions                                           */
/* ------------------------------------------------------------------ */
std::vector<std::string> get_main_defined_functions(
    const std::vector<std::string>& total_funcs)
{
    std::vector<std::string> out;
    for (auto const& f : total_funcs)
        if (f.find("main.") != std::string::npos &&
            f.find("runtime") == std::string::npos)
            out.push_back(split_string(f, ".").back());
    return out;
}

/* ------------------------------------------------------------------ */
/* get_all_imports                                                      */
/* ------------------------------------------------------------------ */
std::vector<std::string> get_all_imports(const std::vector<std::string>& func_names)
{
    std::vector<std::string> imports;
    for (auto const& fn : func_names)
    {
        if (fn.find("github.com") != std::string::npos) {
            std::string pkg = "github.com/" + split_string(split_string(fn, "github.com/")[1], ".")[0];
            if (std::find(imports.begin(), imports.end(), pkg) == imports.end())
                imports.push_back(pkg);
        } else if (fn.find(".") != std::string::npos) {
            std::string pkg = split_string(fn, ".")[0];
            if (pkg != "main" && pkg != "__x86" &&
                std::find(imports.begin(), imports.end(), pkg) == imports.end())
                imports.push_back(pkg);
        }
    }
    return imports;
}