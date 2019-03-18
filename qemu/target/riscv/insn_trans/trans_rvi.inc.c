/*
 * RISC-V translation routines for the RVXI Base Integer Instruction Set.
 *
 * Copyright (c) 2016-2017 Sagar Karandikar, sagark@eecs.berkeley.edu
 * Copyright (c) 2018 Peer Adelt, peer.adelt@hni.uni-paderborn.de
 *                    Bastian Koppelmann, kbastian@mail.uni-paderborn.de
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2 or later, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program.  If not, see <http://www.gnu.org/licenses/>.
 */

static bool trans_lui(DisasContext *ctx, arg_lui *a)
{
    if (a->rd != 0) {
        TCGContext *tcg_ctx = ctx->uc->tcg_ctx;
        tcg_gen_movi_tl(tcg_ctx, tcg_ctx->cpu_gpr[a->rd], a->imm);
    }
    return true;
}

static bool trans_auipc(DisasContext *ctx, arg_auipc *a)
{
    if (a->rd != 0) {
        TCGContext *tcg_ctx = ctx->uc->tcg_ctx;
        tcg_gen_movi_tl(tcg_ctx, tcg_ctx->cpu_gpr[a->rd], a->imm + ctx->base.pc_next);
    }
    return true;
}

static bool trans_jal(DisasContext *ctx, arg_jal *a)
{
    gen_jal(ctx, a->rd, a->imm);
    return true;
}

static bool trans_jalr(DisasContext *ctx, arg_jalr *a)
{
    gen_jalr(ctx, OPC_RISC_JALR, a->rd, a->rs1, a->imm);
    return true;
}

static bool trans_beq(DisasContext *ctx, arg_beq *a)
{
    gen_branch(ctx, OPC_RISC_BEQ, a->rs1, a->rs2, a->imm);
    return true;
}

static bool trans_bne(DisasContext *ctx, arg_bne *a)
{
    gen_branch(ctx, OPC_RISC_BNE, a->rs1, a->rs2, a->imm);
    return true;
}

static bool trans_blt(DisasContext *ctx, arg_blt *a)
{
    gen_branch(ctx, OPC_RISC_BLT, a->rs1, a->rs2, a->imm);
    return true;
}

static bool trans_bge(DisasContext *ctx, arg_bge *a)
{
    gen_branch(ctx, OPC_RISC_BGE, a->rs1, a->rs2, a->imm);
    return true;
}

static bool trans_bltu(DisasContext *ctx, arg_bltu *a)
{
    gen_branch(ctx, OPC_RISC_BLTU, a->rs1, a->rs2, a->imm);
    return true;
}

static bool trans_bgeu(DisasContext *ctx, arg_bgeu *a)
{

    gen_branch(ctx, OPC_RISC_BGEU, a->rs1, a->rs2, a->imm);
    return true;
}