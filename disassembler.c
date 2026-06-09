#include "disassembler.h"
#include <capstone/capstone.h>
#include <string.h>
#include <stdio.h>

unsigned int disassemble(
    unsigned char* bytes,
    unsigned int   max,
    uint64_t       offset,
    char*          output,
    uint64_t*      resolved_addr)
{
    csh       handle;
    cs_insn*  insn;
    size_t    count;
    unsigned int consumed = 1;

    if (resolved_addr)
        *resolved_addr = 0;

    output[0] = '\0';

    if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK)
    {
        snprintf(output, 255, "db 0x%02x", bytes[0]);
        return 1;
    }

    cs_option(handle, CS_OPT_SYNTAX,  CS_OPT_SYNTAX_INTEL);
    cs_option(handle, CS_OPT_DETAIL,  CS_OPT_ON);

    count = cs_disasm(handle, bytes, (size_t)max, (uint64_t)offset, 1, &insn);

    if (count > 0)
    {
        snprintf(output, 255, "%s %s", insn[0].mnemonic, insn[0].op_str);
        consumed = (unsigned int)insn[0].size;

        /* Resolve RIP-relative address for LEA / CALL / JMP / Jcc */
        if (resolved_addr && insn[0].detail)
        {
            cs_x86* x86 = &insn[0].detail->x86;
            for (int op = 0; op < x86->op_count; op++)
            {
                cs_x86_op* xop = &x86->operands[op];
                if (xop->type == X86_OP_MEM && xop->mem.base == X86_REG_RIP)
                {
                    /* RIP value = address of *next* instruction */
                    *resolved_addr = (uint64_t)((int64_t)(insn[0].address + insn[0].size) +
                                                 (int64_t)xop->mem.disp);
                    break;
                }
                if (xop->type == X86_OP_IMM)
                {
                    *resolved_addr = (uint64_t)xop->imm;
                    break;
                }
            }
        }

        cs_free(insn, count);
    }
    else
    {
        snprintf(output, 255, "db 0x%02x", bytes[0]);
        consumed = 1;
    }

    cs_close(&handle);
    return consumed;
}