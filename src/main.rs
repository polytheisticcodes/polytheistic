// use std::path::PathBuf;

use arc_swap::ArcSwap;
use num_derive::*;
// use rbpf::disassembler;
use rbpf::ebpf;
use rbpf::ebpf::Insn;
use std::sync::{Arc, Weak};

fn main() {
    println!("Hello, world!");

    // This is the eBPF program, in the form of bytecode instructions.
    let prog = &[
        0xb4, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov32 r0, 0
        0xb4, 0x01, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, // mov32 r1, 2
        0x04, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, // add32 r0, 1
        0x0c, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // add32 r0, r1
        0x95, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // exit
    ];

    // Instantiate a struct EbpfVmNoData. This is an eBPF VM for programs that
    // takes no packet data in argument.
    // The eBPF program is passed to the constructor.
    let vm = rbpf::EbpfVmNoData::new(Some(prog)).unwrap();

    let run = vm.execute_program();

    println!("Program run: {:?}", run);
    // Execute (interpret) the program. No argument required for this VM.
    assert_eq!(run.unwrap(), 0x6);

    let ins = to_insr_vec(prog);
    EbpfInstruction::build_graph(&ins);
    return;
    // disassembler::disassemble(prog);
    // println!("\n\nOther example\n\n");
    // let filename = "obj_files/load_elf__block_a_port.o";

    // let path = PathBuf::from(filename);
    // let file = match elf::File::open_path(&path) {
    //     Ok(f) => f,
    //     Err(e) => panic!("Error: {:?}", e),
    // };

    // let text_scn = match file.get_section(".classifier") {
    //     Some(s) => s,
    //     None => panic!("Failed to look up .classifier section"),
    // };

    // let prog = &text_scn.data;

    // disassembler::disassemble(prog);

    // let _e: Option<EbpfInstruction> = EbpfInstruction::from_u8(ebpf::LD_ABS_B);
}

#[derive(Debug, Clone)]
pub struct GraphHolder {
    instructions: Arc<Vec<Arc<MetaInst>>>,
    groups: Arc<Vec<Vec<Arc<MetaInst>>>>,
}

impl GraphHolder {
    pub fn new(ins: &[Insn]) -> Arc<GraphHolder> {
        let tv = Arc::new(MetaInst::new_vec(ins));
        let groups = tv
            .split_inclusive(|v| v.instr.is_branch())
            .map(|v| {
                let mut ret = Vec::new();
                ret.extend_from_slice(v);
                ret
            })
            .collect();
        let ret = Arc::new(GraphHolder {
            instructions: tv.clone(),
            groups: Arc::new(groups),
        });

        let to_set = Arc::new(Some(Arc::downgrade(&ret)));
        for i in tv.iter() {
            i.set_part_of(&to_set);
        }

        ret
    }
}

/// Holds the underlying `Insn` along with other information
/// about the instruction
#[derive(Debug)]
pub struct MetaInst {
    pub base: Insn,
    pub instr: EbpfInstruction,
    pub pos: usize,
    pub part_of: ArcSwap<Option<Weak<GraphHolder>>>,
}

impl Clone for MetaInst {
    fn clone(&self) -> Self {
        MetaInst {
            base: self.base.clone(),
            instr: self.instr.clone(),
            pos: self.pos,
            part_of: ArcSwap::new(self.part_of.load().clone()),
        }
    }
}

impl PartialEq for MetaInst {
    fn eq(&self, other: &Self) -> bool {
        self.base == other.base && self.instr == other.instr && self.pos == other.pos
        /* FIXME -- figure out if they refer to the same underlying object &&
        self.part_of.load() == other.part_of.load() */
    }
}

impl MetaInst {
    pub fn new_vec(ins: &[Insn]) -> Vec<Arc<MetaInst>> {
        ins.iter()
            .enumerate()
            .map(|(pos, insn)| {
                Arc::new(MetaInst {
                    instr: EbpfInstruction::from(insn),
                    base: insn.clone(),
                    pos: pos,
                    part_of: ArcSwap::new(Arc::new(None)),
                })
            })
            .collect()
    }

    pub fn set_part_of(&self, to: &Arc<Option<Weak<GraphHolder>>>) -> &Self {
        self.part_of.store(to.clone());
        self
    }

    pub fn get_graph(&self) -> Option<Arc<GraphHolder>> {
        match **self.part_of.load() {
            Some(ref weak) => weak.upgrade(),
            None => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct InstAction {
    pub inst: Arc<MetaInst>,
}

impl InstAction {
    pub fn new(inst: &Arc<MetaInst>) -> InstAction {
        InstAction { inst: inst.clone() }
    }

    /// is the instruction an 8 bit instruction?
    pub fn is_8bit(&self) -> bool {
        self.inst.instr.is_8bit()
    }

    /// is the instruction an 16 bit instruction?
    pub fn is_16bit(&self) -> bool {
        self.inst.instr.is_16bit()
    }

    /// is the instruction an 32 bit instruction?
    pub fn is_32bit(&self) -> bool {
        self.inst.instr.is_32bit()
    }

    /// is the instruction an 64 bit instruction?
    pub fn is_64bit(&self) -> bool {
        self.inst.instr.is_64bit()
    }

    /// is the instruction a constant
    pub fn is_const(&self) -> bool {
        self.inst.instr.is_const()
    }
}

/// The set of eBPF instructions
#[allow(non_camel_case_types)]
#[derive(FromPrimitive, ToPrimitive, Debug, PartialEq, Eq, Clone)]
pub enum EbpfInstruction {
    LD_ABS_B = ebpf::LD_ABS_B as isize,
    LD_ABS_H = ebpf::LD_ABS_H as isize,
    LD_ABS_W = ebpf::LD_ABS_W as isize,
    LD_ABS_DW = ebpf::LD_ABS_DW as isize,
    LD_IND_B = ebpf::LD_IND_B as isize,
    LD_IND_H = ebpf::LD_IND_H as isize,
    LD_IND_W = ebpf::LD_IND_W as isize,
    LD_IND_DW = ebpf::LD_IND_DW as isize,

    LD_DW_IMM = ebpf::LD_DW_IMM as isize,

    // BPF_LDX class
    LD_B_REG = ebpf::LD_B_REG as isize,
    LD_H_REG = ebpf::LD_H_REG as isize,
    LD_W_REG = ebpf::LD_W_REG as isize,
    LD_DW_REG = ebpf::LD_DW_REG as isize,

    // BPF_ST class
    ST_B_IMM = ebpf::ST_B_IMM as isize,
    ST_H_IMM = ebpf::ST_H_IMM as isize,
    ST_W_IMM = ebpf::ST_W_IMM as isize,
    ST_DW_IMM = ebpf::ST_DW_IMM as isize,

    // BPF_STX class
    ST_B_REG = ebpf::ST_B_REG as isize,
    ST_H_REG = ebpf::ST_H_REG as isize,
    ST_W_REG = ebpf::ST_W_REG as isize,
    ST_DW_REG = ebpf::ST_DW_REG as isize,
    ST_W_XADD = ebpf::ST_W_XADD as isize,
    ST_DW_XADD = ebpf::ST_DW_XADD as isize,

    // BPF_ALU class
    ADD32_IMM = ebpf::ADD32_IMM as isize,
    ADD32_REG = ebpf::ADD32_REG as isize,
    SUB32_IMM = ebpf::SUB32_IMM as isize,
    SUB32_REG = ebpf::SUB32_REG as isize,
    MUL32_IMM = ebpf::MUL32_IMM as isize,
    MUL32_REG = ebpf::MUL32_REG as isize,
    DIV32_IMM = ebpf::DIV32_IMM as isize,
    DIV32_REG = ebpf::DIV32_REG as isize,
    OR32_IMM = ebpf::OR32_IMM as isize,
    OR32_REG = ebpf::OR32_REG as isize,
    AND32_IMM = ebpf::AND32_IMM as isize,
    AND32_REG = ebpf::AND32_REG as isize,
    LSH32_IMM = ebpf::LSH32_IMM as isize,
    LSH32_REG = ebpf::LSH32_REG as isize,
    RSH32_IMM = ebpf::RSH32_IMM as isize,
    RSH32_REG = ebpf::RSH32_REG as isize,
    NEG32 = ebpf::NEG32 as isize,
    MOD32_IMM = ebpf::MOD32_IMM as isize,
    MOD32_REG = ebpf::MOD32_REG as isize,
    XOR32_IMM = ebpf::XOR32_IMM as isize,
    XOR32_REG = ebpf::XOR32_REG as isize,
    MOV32_IMM = ebpf::MOV32_IMM as isize,
    MOV32_REG = ebpf::MOV32_REG as isize,
    ARSH32_IMM = ebpf::ARSH32_IMM as isize,
    ARSH32_REG = ebpf::ARSH32_REG as isize,
    LE = ebpf::LE as isize,
    BE = ebpf::BE as isize,

    // BPF_ALU64 class
    ADD64_IMM = ebpf::ADD64_IMM as isize,
    ADD64_REG = ebpf::ADD64_REG as isize,
    SUB64_IMM = ebpf::SUB64_IMM as isize,
    SUB64_REG = ebpf::SUB64_REG as isize,
    MUL64_IMM = ebpf::MUL64_IMM as isize,
    MUL64_REG = ebpf::MUL64_REG as isize,
    DIV64_IMM = ebpf::DIV64_IMM as isize,
    DIV64_REG = ebpf::DIV64_REG as isize,
    OR64_IMM = ebpf::OR64_IMM as isize,
    OR64_REG = ebpf::OR64_REG as isize,
    AND_64_IMM = ebpf::AND64_IMM as isize,
    AND64_REG = ebpf::AND64_REG as isize,
    LSH64_IMM = ebpf::LSH64_IMM as isize,
    LSH64_REG = ebpf::LSH64_REG as isize,
    RSH64_IMM = ebpf::RSH64_IMM as isize,
    RSH64_REG = ebpf::RSH64_REG as isize,
    NEG64 = ebpf::NEG64 as isize,
    MOD64_IMM = ebpf::MOD64_IMM as isize,
    MOD64_REG = ebpf::MOD64_REG as isize,
    XOR64_IMM = ebpf::XOR64_IMM as isize,
    XOR64_REG = ebpf::XOR64_REG as isize,
    MOV64_IMM = ebpf::MOV64_IMM as isize,
    MOV64_REG = ebpf::MOV64_REG as isize,
    ARSH64_IMM = ebpf::ARSH64_IMM as isize,
    ARSH64_REG = ebpf::ARSH64_REG as isize,

    // BPF_JMP class
    JA = ebpf::JA as isize,
    JEQ_IMM = ebpf::JEQ_IMM as isize,
    JEQ_REG = ebpf::JEQ_REG as isize,
    JGT_IMM = ebpf::JGT_IMM as isize,
    JGT_REG = ebpf::JGT_REG as isize,
    JGE_IMM = ebpf::JGE_IMM as isize,
    JGE_REG = ebpf::JGE_REG as isize,
    JLT_IMM = ebpf::JLT_IMM as isize,
    JLT_REG = ebpf::JLT_REG as isize,
    JLE_IMM = ebpf::JLE_IMM as isize,
    JLE_REG = ebpf::JLE_REG as isize,
    JSET_IMM = ebpf::JSET_IMM as isize,
    JSET_REG = ebpf::JSET_REG as isize,
    JNE_IMM = ebpf::JNE_IMM as isize,
    JNE_REG = ebpf::JNE_REG as isize,
    JSGT_IMM = ebpf::JSGT_IMM as isize,
    JSGT_REG = ebpf::JSGT_REG as isize,
    JSGE_IMM = ebpf::JSGE_IMM as isize,
    JSGE_REG = ebpf::JSGE_REG as isize,
    JSLT_IMM = ebpf::JSLT_IMM as isize,
    JSLT_REG = ebpf::JSLT_REG as isize,
    JSLE_IMM = ebpf::JSLE_IMM as isize,
    JSLE_REG = ebpf::JSLE_REG as isize,
    CALL = ebpf::CALL as isize,
    TAIL_CALL = ebpf::TAIL_CALL as isize,
    EXIT = ebpf::EXIT as isize,
}

impl EbpfInstruction {
    pub const CLASS_MASK: u8 = 0x7;
    pub const SIZE_MASK: u8 = 0x18;
    //pub const

    /// convert from a byte to the corresponding eBPF instruction
    pub fn from_u8(n: u8) -> Option<Self> {
        num::FromPrimitive::from_u8(n)
    }

    /// Convert from an rBPF `Insn` into an instruction
    pub fn from(n: &Insn) -> Self {
        // not super keen on `unwrap`, but in this case,
        // the `Insn` must also be a valid instruction
        num::FromPrimitive::from_u8(n.opc).unwrap()
    }

    pub fn is_ld_immediate(&self) -> bool {
        num::ToPrimitive::to_u8(self).map(|x| x & Self::CLASS_MASK) == Some(ebpf::BPF_LD)
    }

    pub fn is_ld_reg(&self) -> bool {
        num::ToPrimitive::to_u8(self).map(|x| x & Self::CLASS_MASK) == Some(ebpf::BPF_LDX)
    }

    pub fn is_st_immediate(&self) -> bool {
        num::ToPrimitive::to_u8(self).map(|x| x & Self::CLASS_MASK) == Some(ebpf::BPF_ST)
    }

    pub fn is_st_reg(&self) -> bool {
        num::ToPrimitive::to_u8(self).map(|x| x & Self::CLASS_MASK) == Some(ebpf::BPF_STX)
    }

    pub fn is_branch(&self) -> bool {
        num::ToPrimitive::to_u8(self).map(|x| x & Self::CLASS_MASK) == Some(ebpf::BPF_JMP)
    }

    pub fn is_alu(&self) -> bool {
        let tmp = num::ToPrimitive::to_u8(self).map(|x| x & Self::CLASS_MASK);

        tmp == Some(ebpf::BPF_ALU) || tmp == Some(ebpf::BPF_ALU64)
    }

    /// Return true if the instruction is a branch instruction
    pub fn is_branch_insn(ins: &Insn) -> bool {
        Self::from(ins).is_branch()
    }

    /// is the instruction an 8 bit instruction?
    pub fn is_8bit(&self) -> bool {
        num::ToPrimitive::to_u8(self).map(|x| x & 0x18) == Some(ebpf::BPF_B)
    }

    /// is the instruction an 16 bit instruction?
    pub fn is_16bit(&self) -> bool {
        num::ToPrimitive::to_u8(self).map(|x| x & ebpf::BPF_H) == Some(ebpf::BPF_H)
    }

    /// is the instruction an 8 bit instruction?
    pub fn is_32bit(&self) -> bool {
        num::ToPrimitive::to_u8(self).map(|x| x & ebpf::BPF_W) == Some(ebpf::BPF_W)
    }

    /// is the instruction an 64 bit instruction?
    pub fn is_64bit(&self) -> bool {
        num::ToPrimitive::to_u8(self).map(|x| x & ebpf::BPF_DW) == Some(ebpf::BPF_DW)
    }

    /// is the instruction a constant
    pub fn is_const(&self) -> bool {
        (self.is_ld_immediate() || self.is_alu())
            && num::ToPrimitive::to_u8(self).map(|x| x & 0x8) == Some(0)
    }

    pub fn build_graph(ins: &[Insn]) -> usize {
        let i2 = MetaInst::new_vec(ins);
        let groups = i2.split_inclusive(|v| v.instr.is_branch());
        for g in groups {
            for v in g {
                println!("Instruction {:?} is const {}", v, v.instr.is_const());
            }
            println!("Group {:?}", g);
        }
        42
    }
}

pub fn to_insr_vec(prog: &[u8]) -> Vec<Insn> {
    ebpf::to_insn_vec(prog)
}
