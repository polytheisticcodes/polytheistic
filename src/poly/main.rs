use polytheistic::*;

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
