#pragma once
#include <iostream>
#include <string>
#include <sstream>
#include <vector>
#include <boost/format.hpp>
#include <algorithm>
#include <array>
#include <map>
#include <queue>
#include <chrono>
#include <cstdint>
#include <elf.h>

extern "C" {
#include "disassembler.h"
}

/* ------------------------------------------------------------------ */
/*  x86-64 instruction enum                                             */
/* ------------------------------------------------------------------ */
enum Instruction
{
    AAA, AAD, AAM, AAS,
    ADC, ADD, AND,
    CALL,
    CBW, CLC, CLD, CLI, CMC,
    CMP, CMPSB, CMPSW,
    CWD, DAA, DAS, DEC,
    DIV, ESC, HLT,
    IDIV, IMUL,
    _IN, INC, _INT, INTO, IRET,
    JA, JAE, JB, JBE, JC, JE,
    JG, JGE, JL, JLE,
    JNA, JNAE, JNB, JNBE, JNC, JNE,
    JNG, JNGE, JNL, JNLE,
    JNO, JNP, JNS, JNZ,
    JO, JP, JPE, JPO, JS, JZ,
    JCXZ, JMP,
    LAHF, LDS, LEA, LES,
    LOCK, LODSB, LODSW, LOOP,
    MOV, MOVSB, MOVSW,
    MUL, NEG, NOP, NOT,
    OR, _OUT,
    POP, POPF, PUSH, PUSHF,
    RCL, RCR,
    REP, REPE, REPNE, REPNZ, REPZ,
    RET, RETN, RETF,
    ROL, ROR, SAHF,
    SAL, SAR, SBB,
    SCASB, SCASW,
    SHL, SHR,
    STC, STD, STI,
    STOSB, STOSW,
    SUB, TEST, WAIT,
    XCHG, XLAT, XOR,
    /* 64-bit extras */
    MOVSX, MOVZX, MOVSXD,
    SYSCALL, ENDBR64,
    CMOVE, CMOVNE, CMOVL, CMOVLE, CMOVG, CMOVGE,
    CMOVA, CMOVAE, CMOVB, CMOVBE,
    SETNE, SETE, SETL, SETLE, SETG, SETGE,
    UNDEFINED
};

/* ------------------------------------------------------------------ */
/*  Per-instruction buffer                                              */
/* ------------------------------------------------------------------ */
struct IBuffer
{
    std::string  raw_asm;
    Instruction  instruction  = Instruction::UNDEFINED;
    std::vector<std::string> raw_bytes;
    uint64_t     address      = 0xFFFFFFFFFFFFFFFFULL;
    uint64_t     resolved_addr = 0;   // RIP-relative or immediate target VA
};

/* ------------------------------------------------------------------ */
/*  A decoded Go function                                               */
/* ------------------------------------------------------------------ */
struct Function
{
    uint64_t     start_addr;
    uint64_t     end_addr   = 0;
    std::string  function_name;
    std::vector<IBuffer> ibuffers;
    bool         from_main_pkg = false;
};

/* ------------------------------------------------------------------ */
/*  Message passed to translate_function / translate_block             */
/* ------------------------------------------------------------------ */
struct TMessage
{
    Function*              function        = nullptr;
    std::vector<Function>* all_functions   = nullptr;
    uint64_t               jmp_addr        = 0xFFFFFFFFFFFFFFFFULL;
    char*                  buffer          = nullptr;
    size_t                 b_size          = 0;

    /* .rodata / .text section info for VA → file-offset conversion */
    uint64_t               rodata_va       = 0;
    uint64_t               rodata_offset   = 0;
    uint64_t               rodata_size     = 0;
    uint64_t               text_va         = 0;
    uint64_t               text_offset     = 0;

    std::vector<uint32_t>* instructions_used = nullptr;
    int                    indent_level    = 1;
    bool                   compress        = false;
};

/* ------------------------------------------------------------------ */
/*  Go amd64 function-prologue signatures                               */
/*                                                                      */
/*  Go 1.17+ (register ABI, R14 = goroutine ptr):                      */
/*    CMPQ SP, 0x10(R14)  →  49 3B 66 10                               */
/*                                                                      */
/*  Go < 1.17 (TLS-based):                                             */
/*    MOV FS:0xFFFFFFF8, CX  →  64 48 8B 0C 25 F8 FF FF FF            */
/* ------------------------------------------------------------------ */
static const unsigned char gofunc_new_bytes[] = { 0x49, 0x3B, 0x66, 0x10 };
static const unsigned char gofunc_old_bytes[] = { 0x64, 0x48, 0x8B, 0x0C, 0x25 };

/* Sentinel */
const std::string tab_string = "\t";

/* ------------------------------------------------------------------ */
/*  Instruction name → enum map                                         */
/* ------------------------------------------------------------------ */
static const std::map<std::string, Instruction> instructions_map
{
    { "aaa",      AAA  }, { "aad",     AAD  }, { "aam",   AAM  }, { "aas",   AAS  },
    { "adc",      ADC  }, { "add",     ADD  }, { "and",   AND  },
    { "call",     CALL },
    { "cbw",      CBW  }, { "clc",     CLC  }, { "cld",   CLD  }, { "cli",   CLI  },
    { "cmc",      CMC  }, { "cmp",     CMP  }, { "cmpsb", CMPSB}, { "cmpsw", CMPSW},
    { "cwd",      CWD  }, { "daa",     DAA  }, { "das",   DAS  }, { "dec",   DEC  },
    { "div",      DIV  }, { "esc",     ESC  }, { "hlt",   HLT  },
    { "idiv",     IDIV }, { "imul",    IMUL },
    { "in",       _IN  }, { "inc",     INC  }, { "int",   _INT }, { "into",  INTO },
    { "iret",     IRET },
    { "ja",       JA   }, { "jae",     JAE  }, { "jb",    JB   }, { "jbe",   JBE  },
    { "jc",       JC   }, { "je",      JE   }, { "jg",    JG   }, { "jge",   JGE  },
    { "jl",       JL   }, { "jle",     JLE  }, { "jna",   JNA  }, { "jnae",  JNAE },
    { "jnb",      JNB  }, { "jnbe",    JNBE }, { "jnc",   JNC  }, { "jne",   JNE  },
    { "jng",      JNG  }, { "jnge",    JNGE }, { "jnl",   JNL  }, { "jnle",  JNLE },
    { "jno",      JNO  }, { "jnp",     JNP  }, { "jns",   JNS  }, { "jnz",   JNZ  },
    { "jo",       JO   }, { "jp",      JP   }, { "jpe",   JPE  }, { "jpo",   JPO  },
    { "js",       JS   }, { "jz",      JZ   }, { "jcxz",  JCXZ }, { "jmp",   JMP  },
    { "lahf",     LAHF }, { "lds",     LDS  }, { "lea",   LEA  }, { "les",   LES  },
    { "lock",     LOCK }, { "lodsb",   LODSB}, { "lodsw", LODSW}, { "loop",  LOOP },
    { "mov",      MOV  }, { "movsb",   MOVSB}, { "movsw", MOVSW},
    { "mul",      MUL  }, { "neg",     NEG  }, { "nop",   NOP  }, { "not",   NOT  },
    { "or",       OR   }, { "out",     _OUT },
    { "pop",      POP  }, { "popf",    POPF }, { "push",  PUSH }, { "pushf", PUSHF},
    { "rcl",      RCL  }, { "rcr",     RCR  },
    { "rep",      REP  }, { "repe",    REPE }, { "repne", REPNE}, { "repnz", REPNZ},
    { "repz",     REPZ },
    { "ret",      RET  }, { "retn",    RETN }, { "retf",  RETF },
    { "rol",      ROL  }, { "ror",     ROR  }, { "sahf",  SAHF },
    { "sal",      SAL  }, { "sar",     SAR  }, { "sbb",   SBB  },
    { "scasb",    SCASB}, { "scasw",   SCASW},
    { "shl",      SHL  }, { "shr",     SHR  },
    { "stc",      STC  }, { "std",     STD  }, { "sti",   STI  },
    { "stosb",    STOSB}, { "stosw",   STOSW},
    { "sub",      SUB  }, { "test",    TEST }, { "wait",  WAIT },
    { "xchg",     XCHG }, { "xlat",    XLAT }, { "xor",   XOR  },
    /* 64-bit additions */
    { "movsx",    MOVSX   }, { "movzx",  MOVZX  }, { "movsxd", MOVSXD },
    { "syscall",  SYSCALL }, { "endbr64",ENDBR64},
    { "cmove",    CMOVE   }, { "cmovne", CMOVNE }, { "cmovl",  CMOVL  },
    { "cmovle",   CMOVLE  }, { "cmovg",  CMOVG  }, { "cmovge", CMOVGE },
    { "cmova",    CMOVA   }, { "cmovae", CMOVAE }, { "cmovb",  CMOVB  },
    { "cmovbe",   CMOVBE  },
    { "setne",    SETNE   }, { "sete",   SETE   }, { "setl",   SETL   },
    { "setle",    SETLE   }, { "setg",   SETG   }, { "setge",  SETGE  },
};

/* ------------------------------------------------------------------ */
/*  Forward declarations                                                */
/* ------------------------------------------------------------------ */

std::string translate_function(TMessage* tmsg);
std::string translate_block(TMessage* tmsg);

/* Extract Go function names from ELF symtab */
std::vector<std::string> get_function_names(char* buffer, size_t buff_size);

/* Disassemble all Go functions found via ELF symtab */
std::vector<Function> get_all_go_functions(
    char*       buffer,
    size_t      buff_size,
    const std::string& filename
);

/* String extraction from .rodata for a single function */
std::vector<std::string> get_strings_from_function(
    Function*  function,
    char*      buffer,
    size_t     buffer_size,
    uint64_t   rodata_va,
    uint64_t   rodata_offset
);

/* High-level helpers */
std::vector<std::string> get_main_defined_functions(
    const std::vector<std::string>& total_funcs
);

std::vector<std::string> get_all_imports(
    const std::vector<std::string>& func_names
);

std::string find_function_name(
    std::vector<Function>* functions,
    uint64_t               va
);

std::vector<std::string> get_all_function_labels(
    char*       buffer,
    size_t      buff_size,
    const std::string& last_func_name
);

void fix_function_labels(
    std::vector<std::string>* labels,
    std::vector<std::string>* names
);