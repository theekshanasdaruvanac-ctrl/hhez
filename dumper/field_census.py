"""Taint census over lua_State field accesses ([L+disp]) — Phase 4 engine.

One pass over every .pdata function. L = rcx + callee-saved prologue
copies. Tags: ('f',D) reg == [L+D] (or lea-derived address of [L+D],
with offset carry through lea/add/sub +imm so `lea rax,[top+0x10]`
stays top-derivable); ('fd',D,F) reg == [[L+D]+F]. Tags transfer on
reg->reg mov, die on any other def and on every call. The scanner can
lose information but never invents an L-derived value.

Evidence collected (keyed, per-function sets kept):

  family  (topD, ciD, F, const, K)   the lua_gettop shape:
            rax=[L+top]; rdx=[L+ci]; sub rax,[rdx+F]; sub rax,const;
            sar K   -> slot_size = 1<<K = const (when const>0)
  shared  (D,)                       cmp <[L+D]>,[L+D] same-value guard:
            G(L)==G(L') thread chain -> D is l_G (shared across threads)
  topcmp  (Da, D)                    cmp <top-derived (+k*slot)>,[L+D]
            -> stack_last (D != top; Da within offset-carry of top)
  sspair  (D1, D2)                   sub <[L+D1]>, [L+D2] raw field pair
            diffs -> stack / stack_last pairing
  derefs  (D, F)                     tag ('f',D) used as base [reg+F]:
            l_G is walked at many distinct F; counts cross-check family
  ciwalk  (ciD, F)                   same, restricted evidence for
            CallInfo layout (func=+0 confirmed via family F)
  slotnil (topD, T)                  store-imm0 byte to [tagged-top + T]:
            setnilvalue(tt) inside slot -> tt-at-slot offset T
  byte8   (D,)                       cmp byte [L+D], 8 (LUA_TTHREAD probe
            candidate — intersected with family functions at labeling)
  reads/writes  D -> {fn}            raw per-field touch census
"""

from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass, field

from capstone.x86 import X86_REG_RCX, X86_REG_INVALID

from dumper.pe_parser import Image
from dumper.pdata_walker import walk
from dumper.rip_resolver import iter_functions

REGOP, IMMOP, MEM = 1, 2, 3
MAXD = 0x400
CALLEE = {"rbx", "rbp", "rdi", "rsi", "r12", "r13", "r14", "r15"}
CMPISH = frozenset(("cmp", "test"))


def l_aliases(insns) -> set:
    out = {X86_REG_RCX}
    for ins in insns[:64]:
        ops = ins.operands
        if ins.mnemonic == "call":
            break
        if len(ops) != 2 or ops[0].type != REGOP:
            continue
        dn = ins.reg_name(ops[0].reg)
        if ins.mnemonic == "mov" and ops[1].type == REGOP:
            sn = ins.reg_name(ops[1].reg)
            if dn in CALLEE and (sn == "rcx"
                                 or sn in {ins.reg_name(r) for r in out}):
                out.add(ops[0].reg)
        elif dn == "rcx":
            break
    return out


@dataclass
class Evidence:
    family: dict = field(default_factory=lambda: defaultdict(set))
    shared: dict = field(default_factory=lambda: defaultdict(set))
    topcmp: dict = field(default_factory=lambda: defaultdict(set))
    sspair: dict = field(default_factory=lambda: defaultdict(set))
    derefs: dict = field(default_factory=lambda: defaultdict(set))
    slotnil: dict = field(default_factory=lambda: defaultdict(set))
    byte8: dict = field(default_factory=lambda: defaultdict(set))
    reads: dict = field(default_factory=lambda: defaultdict(set))
    writes: dict = field(default_factory=lambda: defaultdict(set))
    n_fn: int = 0


def scan_module(img: Image) -> Evidence:
    inv = walk(img)
    ev = Evidence()
    for f, insns in iter_functions(img, inv):
        _scan_fn(insns, f.begin, ev)
    return ev


def _tagged_offset_carry(mn, imm, tagv):
    """Offset-carry for arithmetic on a value/address loaded from L."""
    if tagv is None or tagv[0] != "f":
        return None
    if mn == "lea" or (mn == "add" and imm is not None):
        return ("f", tagv[1] + imm)
    if mn == "sub" and imm is not None:
        return ("f", tagv[1] - imm)
    return None


def _scan_fn(insns, entry: int, ev: Evidence) -> None:
    if not insns:
        return
    ev.n_fn += 1
    L = l_aliases(insns)
    tag: dict[int, tuple] = {}
    pend: dict[int, tuple] = {}        # reg -> (Da, Db, F, const) diff

    def ldisp(op):
        return (op.mem.disp if op.type == MEM
                and op.mem.index == X86_REG_INVALID
                and op.mem.base in L and 0 <= op.mem.disp <= MAXD
                else None)

    def tagof(op):
        if op is None:
            return None
        if op.type == REGOP:
            return tag.get(op.reg)
        if op.type == MEM and op.mem.index == X86_REG_INVALID:
            d = ldisp(op)
            if d is not None:
                return ("f", d)
            b = op.mem.base
            if b in tag and tag[b][0] == "f":
                return ("fd", tag[b][1], op.mem.disp)
        return None

    for ins in insns:
        mn = ins.mnemonic
        ops = ins.operands
        if mn == "call":
            tag.clear()
            pend.clear()
            continue
        n = len(ops)
        if not n:
            continue
        op0 = ops[0]
        op1 = ops[1] if n > 1 else None
        dreg = op0.reg if op0.type == REGOP else None

        # ---- captures BEFORE kills --------------------------------------
        t_src = tagof(op1)
        t_dst = tag.get(dreg) if dreg is not None else None
        p_dst = pend.get(dreg) if dreg is not None else None

        deref = None
        for op in ops[:2]:
            if op.type == MEM and op.mem.index == X86_REG_INVALID \
                    and op.mem.base in tag and tag[op.mem.base][0] == "f":
                deref = (tag[op.mem.base][1], op.mem.disp)
                break

        # ---- kills --------------------------------------------------------
        if dreg is not None and mn not in CMPISH:
            tag.pop(dreg, None)
            pend.pop(dreg, None)

        # ---- raw field census ----------------------------------------------
        d_dst = ldisp(op0)
        if d_dst is not None and op0.type == MEM:
            (ev.reads if mn in CMPISH else ev.writes)[d_dst].add(entry)
        for i in range(1, n):
            d1 = ldisp(ops[i])
            if d1 is not None:
                ev.reads[d1].add(entry)

        # ---- byte cmp vs 8 (LUA_TTHREAD candidate) ---------------------------
        if mn == "cmp" and n == 2 and op1 is not None \
                and op1.type == IMMOP and op1.imm == 8 \
                and op0.type == MEM and op0.size == 1:
            d = ldisp(op0)
            if d is not None and d <= 0x20:
                ev.byte8[d].add(entry)

        # ---- byte-0 store through a tagged base (setnilvalue tt) --------------
        if mn == "mov" and n == 2 and op0.type == MEM and op1 is not None \
                and op1.type == IMMOP and op1.imm == 0 and op0.size == 1 \
                and op0.mem.index == X86_REG_INVALID \
                and op0.mem.base in tag and tag[op0.mem.base][0] == "f" \
                and 0 <= op0.mem.disp <= MAXD:
            ev.slotnil[(tag[op0.mem.base][1], op0.mem.disp)].add(entry)

        if deref is not None:
            ev.derefs[deref].add(entry)

        # ---- pointer diff family (gettop) + raw field-pair sub ----------------
        if mn == "sub" and dreg is not None and t_dst is not None \
                and t_src is not None:
            if t_dst is not None and t_src is not None:
                if t_dst[0] == "f" and t_src[0] == "fd":
                    pend[dreg] = (t_dst[1], t_src[1], t_src[2], 0)
                elif t_dst[0] == "f" and t_src[0] == "f":
                    pend[dreg] = (t_dst[1], t_src[1], None, 0)
                    ev.sspair[(t_dst[1], t_src[1])].add(entry)
        elif mn in ("add", "sub") and dreg is not None and p_dst is not None \
                and op1 is not None and op1.type == IMMOP \
                and op1.imm <= 0x1000:
            Da, Db, F, cc = p_dst
            cc = cc + op1.imm if mn == "sub" else cc - op1.imm
            pend[dreg] = (Da, Db, F, cc)
        elif mn in ("sar", "shr") and dreg is not None and p_dst is not None:
            K = None
            if op1 is not None and op1.type == IMMOP:
                K = op1.imm
            elif op1 is not None and op1.type == REGOP \
                    and ins.reg_name(op1.reg).endswith("cl"):
                K = "cl"
            if K is not None:
                Da, Db, F, cc = p_dst
                ev.family[(Da, Db, F, cc, K)].add(entry)
                pend.pop(dreg, None)
            else:
                pend.pop(dreg, None)

        # ---- compares: G-share / top-vs-field guards ---------------------------
        if mn == "cmp" and dreg is not None and t_dst is not None \
                and t_src is not None and not (
                    op1 is not None and op1.type == IMMOP):
            if t_dst[0] == "f" and t_src[0] == "f" and t_dst[1] == t_src[1]:
                ev.shared[t_dst[1]].add(entry)
            elif t_dst[0] == "f":
                dr = abs(t_src[1]) if t_src[0] == "f" else t_src[1]
                if t_src[0] in ("f", "fd") and 0 <= dr <= MAXD:
                    ev.topcmp[(t_dst[1], dr)].add(entry)
            elif t_dst[0] == "fd" and t_src[0] == "f":
                dr = t_src[1]
                if 0 <= dr <= MAXD:
                    ev.topcmp[(dr, t_dst[1])].add(entry)
        if mn == "cmp" and dreg is None and op0.type == MEM \
                and 0 <= op0.mem.disp <= MAXD and op0.mem.base in L \
                and op1 is not None and op1.type == REGOP:
            t = tag.get(op1.reg)
            dr = op0.mem.disp
            if t is not None and t[0] == "f":
                ev.topcmp[(t[1], dr)].add(entry)
            if t is not None and t[0] == "f" and t[1] == dr:
                ev.shared[dr].add(entry)

        # ---- (re)tag --------------------------------------------------------------
        if dreg is not None:
            imm = op1.imm if (op1 is not None and op1.type == IMMOP) else None
            carried = None
            if mn == "lea" and op1 is not None and op1.type == MEM:
                if op1.mem.base in L:
                    carried = ("f", op1.mem.disp)          # &L-field
                else:
                    base_tag = tag.get(op1.mem.base)
                    if base_tag is not None and base_tag[0] == "f":
                        carried = ("f", base_tag[1] + op1.mem.disp)
            if carried is None and mn in ("mov", "movzx", "movsx") \
                    and t_src is not None:
                carried = t_src
            if carried is None and mn == "mov" and t_dst is not None \
                    and imm is not None and imm == 0:
                carried = None      # NULL overwrite: definitely untag
            if carried is None and mn in ("add", "sub") \
                    and imm is not None:
                carried = _tagged_offset_carry(mn, imm, t_dst)
            elif carried is None and mn == "mov" and op1 is not None \
                    and op1.type == REGOP and op1.reg in tag \
                    and tag[op1.reg][0] == "fd":
                carried = tag[op1.reg]
            if carried is not None:
                tag[dreg] = carried
            elif mn == "mov" and op1 is not None and op1.type == REGOP \
                    and t_src is not None:
                tag[dreg] = t_src
