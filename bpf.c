/*
 * Copyright (c) 2015 Nicira, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "bpf.h"
#include "dynamic_string.h"
#include "type-props.h"
#include <inttypes.h>

typedef signed int 	int32_t;
typedef signed short 		int16_t;

extern void set_table(uint32_t table);
extern void parse_ins(uint64_t to_parse, uint64_t to_dest,uint32_t tbl);

bool
bpf_execute(const struct bpf_insn code[], size_t n,
            const struct bpf_ops *ops, void *aux,
            uint64_t regs[10])
{
    for (const struct bpf_insn *i = code; i < &code[n]; i++) {
        uint64_t src = regs[i->src_reg];
        uint64_t *dst = &regs[i->dst_reg];
        uint64_t kx = BPF_SRC(i->code) == BPF_X ? src : i->imm;

        switch (i->code) {

        case BPF_SET_TBL:
            printf("Set Table Instruction\n");
            set_table(i->imm);
            break;

        case BPF_PARSE:
            printf("Parse Instruction\n");
            printf("reg 1  %x  reg 2 %x\n", i->src_reg, i->dst_reg);
            printf("reg val 1  %llx  reg val 2 %llx\n", regs[i->src_reg], regs[i->dst_reg]);
            parse_ins(regs[i->src_reg], regs[i->dst_reg], i->imm);
            break;
 
        case BPF_LD | BPF_IMM | BPF_DW:
            regs[i->dst_reg] = ((uint32_t) i[0].imm
                                | ((uint64_t) i[1].imm << 32));
            i++;
            break;

#define MEM(SUFFIX, WIDTH)                                              \
        case BPF_LDX | BPF_MEM | BPF_##SUFFIX:                          \
            if (!ops->load(src + i->off, dst, WIDTH, aux)) {            \
                return false;                                           \
            }                                                           \
            break;                                                      \
        case BPF_STX | BPF_MEM | BPF_##SUFFIX:                          \
            if (!ops->store(*dst + i->off, src, WIDTH, aux)) {          \
                return false;                                           \
            }                                                           \
            break;                                                      \
        case BPF_ST | BPF_MEM | BPF_##SUFFIX:                           \
            if (!ops->store(*dst + i->off, i->imm, WIDTH, aux)) {       \
                return false;                                           \
            }                                                           \
            break;
        MEM(DW, 8);
        MEM(W, 4);
        MEM(H, 2);
        MEM(B, 1);
#undef MEM

        case BPF_JMP | BPF_JA:
            i += i->off;
            break;

        case BPF_JMP | BPF_JEQ | BPF_K:
        case BPF_JMP | BPF_JEQ | BPF_X:
            if (*dst == kx) {
                i += i->off;
            }
            break;
        case BPF_JMP | BPF_JGT | BPF_K:
        case BPF_JMP | BPF_JGT | BPF_X:
            if (*dst > kx) {
                i += i->off;
            }
            break;
        case BPF_JMP | BPF_JGE | BPF_K:
        case BPF_JMP | BPF_JGE | BPF_X:
            if (*dst >= kx) {
                i += i->off;
            }
            break;
        case BPF_JMP | BPF_JSET | BPF_K:
        case BPF_JMP | BPF_JSET | BPF_X:
            if (*dst & kx) {
                i += i->off;
            }
            break;
        case BPF_JMP | BPF_JNE | BPF_K:
        case BPF_JMP | BPF_JNE | BPF_X:
            if (*dst != kx) {
                i += i->off;
            }
            break;
        case BPF_JMP | BPF_JSGT | BPF_K:
        case BPF_JMP | BPF_JSGT | BPF_X:
            if ((int64_t) *dst > (int64_t) kx) {
                i += i->off;
            }
            break;
        case BPF_JMP | BPF_JSGE | BPF_K:
        case BPF_JMP | BPF_JSGE | BPF_X:
            if ((int64_t) *dst >= (int64_t) kx) {
                i += i->off;
            }
            break;

        case BPF_JMP | BPF_EXIT:
            return true;

#define ALU_OP(SUFFIX, OPERATOR)                            \
        case BPF_ALU | BPF_##SUFFIX | BPF_K:                \
        case BPF_ALU | BPF_##SUFFIX | BPF_X:                \
            *dst = (uint32_t) *dst OPERATOR (uint32_t) kx;  \
            break;                                          \
        case BPF_ALU64 | BPF_##SUFFIX | BPF_K:              \
        case BPF_ALU64 | BPF_##SUFFIX | BPF_X:              \
            *dst = *dst OPERATOR kx;                        \
            break;

            ALU_OP(ADD, +);
            ALU_OP(SUB, -);
            ALU_OP(MUL, *);
            ALU_OP(DIV, /);
            ALU_OP(OR, |);
            ALU_OP(AND, &);
            ALU_OP(LSH, <<);
            ALU_OP(RSH, >>);
            ALU_OP(MOD, %);
            ALU_OP(XOR, ^);
#undef ALU_OP

        case BPF_ALU | BPF_NEG:
            *dst = (uint32_t) -*dst;
            break;
        case BPF_ALU64 | BPF_NEG:
            *dst = -*dst;
            break;

        case BPF_ALU | BPF_MOV | BPF_K:
        case BPF_ALU | BPF_MOV | BPF_X:
            *dst = (uint32_t) kx;
            break;
        case BPF_ALU64 | BPF_MOV | BPF_K:
        case BPF_ALU64 | BPF_MOV | BPF_X:
            *dst = kx;
            break;

        case BPF_ALU64 | BPF_ARSH | BPF_K:
        case BPF_ALU64 | BPF_ARSH | BPF_X:
            *dst = *(int64_t *)dst >> kx;
            break;

        case BPF_ALU | BPF_END | BPF_TO_BE:
            switch (i->imm) {
            case 16: *dst = (uint16_t) (*dst); break;
            case 32: *dst = (uint32_t) (*dst); break;
            case 64: *dst = (uint64_t) (*dst); break;
            default: printf("unknown size : %d\n", __LINE__);
            }
            break;

        case BPF_ALU | BPF_END | BPF_TO_LE:
            switch (i->imm) {
            case 16: *dst = (uint16_t) (*dst); break;
            case 32: *dst = (uint32_t) (*dst); break;
            case 64: *dst = (uint64_t) (*dst); break;
            default: printf("unknown size : %d\n", __LINE__);
            }
            break;
        }
    }
    return true;
}

static char
size_char(uint8_t code)
{
    switch (BPF_SIZE(code)) {
    case BPF_DW: return 'd';
    case BPF_W: return 'w';
    case BPF_H: return 'h';
    case BPF_B: return 'b';
    }
    printf("unknown  : %d\n", __LINE__);
    return 0;
}

static const char *
cond_name(uint8_t code)
{
    switch (BPF_OP(code)) {
    case BPF_JEQ: return "==";
    case BPF_JGT: return ">";
    case BPF_JGE: return ">=";
    case BPF_JSET: return "&";
    case BPF_JNE: return "!=";
    case BPF_JSGT: return "s>";
    case BPF_JSGE: return "s>=";
    }
    printf("unknown  : %d\n", __LINE__);
    return 0;
}

static const char *
alu_name(uint8_t code)
{
    switch (BPF_OP(code)) {
    case BPF_ADD: return "add";
    case BPF_SUB: return "sub";
    case BPF_MUL: return "mul";
    case BPF_DIV: return "div";
    case BPF_OR: return "or";
    case BPF_AND: return "and";
    case BPF_LSH: return "lsh";
    case BPF_RSH: return "rsh";
    case BPF_NEG: return "neg";
    case BPF_MOD: return "mod";
    case BPF_XOR: return "xor";
    case BPF_MOV: return "mov";
    case BPF_ARSH: return "arsh";
    }
    printf("unknown  : %d\n", __LINE__);
    return 0;
}

static char
alu_size_char(uint8_t code)
{
    return BPF_CLASS(code) == BPF_ALU ? 'w' : 'd';
}

#if 0
void
bpf_disassemble(const struct bpf_insn code[], size_t n,
                char **notes, size_t n_notes, struct ds *s)
{
    unsigned int ofs;

    for (ofs = 0; ofs < n; ofs++) {
        const struct bpf_insn *i = &code[ofs];
        char kx[1 + INT_STRLEN(int32_t) + 1];
        char disp[INT_STRLEN(int16_t) + 1];

        const char *note = ofs < n_notes ? notes[ofs] : NULL;
        if (note) {
            ds_put_format(s, "%s\n", note);
        }

        if (BPF_SRC(i->code) == BPF_X) {
            sprintf(kx, "r%d", i->src_reg);
        } else if (i->imm >= 0 && i->imm < 10) {
            sprintf(kx, "#%x", i->imm);
        } else {
            sprintf(kx, "#0x%"PRIx32, i->imm);
        }
        if (i->off > 0) {
            sprintf(disp, "%#"PRIx16, i->off);
        } else if (i->off < 0) {
            sprintf(disp, "%"PRId16, i->off);
        } else {
            disp[0] = '\0';
        }

        ds_put_format(s, "%4u: ", ofs);
        switch (i->code) {
        case BPF_LD | BPF_IMM | BPF_DW:
            ds_put_format(s, "ld #%#"PRIx64", r%u",
                          (uint32_t) i[0].imm | ((uint64_t) i[1].imm << 32), i->dst_reg);
            ofs++;
            break;

        case BPF_LDX | BPF_MEM | BPF_DW:
        case BPF_LDX | BPF_MEM | BPF_W:
        case BPF_LDX | BPF_MEM | BPF_H:
        case BPF_LDX | BPF_MEM | BPF_B:
            ds_put_format(s, "ld%c %s[r%u], r%u",
                          size_char(i->code), disp, i->src_reg, i->dst_reg);
            break;
        case BPF_STX | BPF_MEM | BPF_DW:
        case BPF_STX | BPF_MEM | BPF_W:
        case BPF_STX | BPF_MEM | BPF_H:
        case BPF_STX | BPF_MEM | BPF_B:
            ds_put_format(s, "st%c r%u, %s[r%u]",
                          size_char(i->code), i->src_reg, disp, i->dst_reg);
            break;
        case BPF_ST | BPF_MEM | BPF_DW:
        case BPF_ST | BPF_MEM | BPF_W:
        case BPF_ST | BPF_MEM | BPF_H:
        case BPF_ST | BPF_MEM | BPF_B:
            ds_put_format(s, "st%c #%#"PRIx32", %s[r%u]",
                          size_char(i->code), i->imm, disp, i->dst_reg);
            break;

        case BPF_JMP | BPF_JA:
            ds_put_format(s, "jmp %u", ofs + i->off + 1);
            break;

        case BPF_JMP | BPF_JEQ | BPF_K:
        case BPF_JMP | BPF_JGT | BPF_K:
        case BPF_JMP | BPF_JGE | BPF_K:
        case BPF_JMP | BPF_JSET | BPF_K:
        case BPF_JMP | BPF_JNE | BPF_K:
        case BPF_JMP | BPF_JSGT | BPF_K:
        case BPF_JMP | BPF_JSGE | BPF_K:
        case BPF_JMP | BPF_JEQ | BPF_X:
        case BPF_JMP | BPF_JGT | BPF_X:
        case BPF_JMP | BPF_JGE | BPF_X:
        case BPF_JMP | BPF_JSET | BPF_X:
        case BPF_JMP | BPF_JNE | BPF_X:
        case BPF_JMP | BPF_JSGT | BPF_X:
        case BPF_JMP | BPF_JSGE | BPF_X:
            ds_put_format(s, "if (r%d %s %s) jmp %u",
                          i->dst_reg, cond_name(i->code),
                          kx, ofs + i->off + 1);
            break;

        case BPF_JMP | BPF_EXIT:
            ds_put_cstr(s, "exit");
            break;

        case BPF_ALU | BPF_ADD | BPF_K:
        case BPF_ALU | BPF_SUB | BPF_K:
        case BPF_ALU | BPF_MUL | BPF_K:
        case BPF_ALU | BPF_DIV | BPF_K:
        case BPF_ALU | BPF_OR | BPF_K:
        case BPF_ALU | BPF_AND | BPF_K:
        case BPF_ALU | BPF_LSH | BPF_K:
        case BPF_ALU | BPF_RSH | BPF_K:
        case BPF_ALU | BPF_MOD | BPF_K:
        case BPF_ALU | BPF_XOR | BPF_K:
        case BPF_ALU | BPF_MOV | BPF_K:
        case BPF_ALU64 | BPF_ADD | BPF_K:
        case BPF_ALU64 | BPF_SUB | BPF_K:
        case BPF_ALU64 | BPF_MUL | BPF_K:
        case BPF_ALU64 | BPF_DIV | BPF_K:
        case BPF_ALU64 | BPF_OR | BPF_K:
        case BPF_ALU64 | BPF_AND | BPF_K:
        case BPF_ALU64 | BPF_LSH | BPF_K:
        case BPF_ALU64 | BPF_RSH | BPF_K:
        case BPF_ALU64 | BPF_MOD | BPF_K:
        case BPF_ALU64 | BPF_XOR | BPF_K:
        case BPF_ALU64 | BPF_MOV | BPF_K:
        case BPF_ALU | BPF_ADD | BPF_X:
        case BPF_ALU | BPF_SUB | BPF_X:
        case BPF_ALU | BPF_MUL | BPF_X:
        case BPF_ALU | BPF_DIV | BPF_X:
        case BPF_ALU | BPF_OR | BPF_X:
        case BPF_ALU | BPF_AND | BPF_X:
        case BPF_ALU | BPF_LSH | BPF_X:
        case BPF_ALU | BPF_RSH | BPF_X:
        case BPF_ALU | BPF_MOD | BPF_X:
        case BPF_ALU | BPF_XOR | BPF_X:
        case BPF_ALU | BPF_MOV | BPF_X:
        case BPF_ALU64 | BPF_ADD | BPF_X:
        case BPF_ALU64 | BPF_SUB | BPF_X:
        case BPF_ALU64 | BPF_MUL | BPF_X:
        case BPF_ALU64 | BPF_DIV | BPF_X:
        case BPF_ALU64 | BPF_OR | BPF_X:
        case BPF_ALU64 | BPF_AND | BPF_X:
        case BPF_ALU64 | BPF_LSH | BPF_X:
        case BPF_ALU64 | BPF_RSH | BPF_X:
        case BPF_ALU64 | BPF_MOD | BPF_X:
        case BPF_ALU64 | BPF_XOR | BPF_X:
        case BPF_ALU64 | BPF_MOV | BPF_X:
            ds_put_format(s, "%s%c %s, r%d",
                          alu_name(i->code), alu_size_char(i->code),
                          kx, i->dst_reg);
            break;

        case BPF_ALU | BPF_NEG:
        case BPF_ALU64 | BPF_NEG:
            ds_put_format(s, "%s%c r%d",
                          alu_name(i->code), alu_size_char(i->code),
                          i->dst_reg);
            break;

        case BPF_ALU | BPF_END | BPF_TO_BE:
            ds_put_format(s, "htobe%c r%d",
                          i->imm == 16 ? 'h' : i->imm == 32 ? 'w' : 'd',
                          i->dst_reg);
            break;

        case BPF_ALU | BPF_END | BPF_TO_LE:
            ds_put_format(s, "htole%c r%d",
                          i->imm == 16 ? 'h' : i->imm == 32 ? 'w' : 'd',
                          i->dst_reg);
            break;

        default:
            printf("unknown  : %d\n", __LINE__);
        }
        ds_put_char(s, '\n');
    }
}
#endif
