use nyxstone::{mcid_flags, Nyxstone, NyxstoneConfig};

fn print_semantic_info(insn: &nyxstone::Instruction) {
    println!("Instruction: {} @ {:#x}", insn.assembly, insn.address);
    print!("  Bytes: ");
    for byte in &insn.bytes {
        print!("{:02x} ", byte);
    }
    println!();

    if let Some(sem) = insn.semantics() {
        println!("  Semantic Info:");
        println!("    - opcode_name: {}", sem.opcode_name);
        println!("    - flags: {:#x}", sem.flags);
        println!("    - target_flags: {:#x}", sem.target_flags);
        if sem.is_branch {
            println!("    - is_branch");
        }
        if sem.is_call {
            println!("    - is_call");
        }
        if sem.is_return {
            println!("    - is_return");
        }
        if sem.is_conditional_branch {
            println!("    - is_conditional_branch");
        }
        if sem.is_unconditional_branch {
            println!("    - is_unconditional_branch");
        }
        if sem.is_indirect_branch {
            println!("    - is_indirect_branch");
        }
        if sem.is_terminator {
            println!("    - is_terminator");
        }
        if sem.is_barrier {
            println!("    - is_barrier");
        }
        if sem.may_load {
            println!("    - may_load");
        }
        if sem.may_store {
            println!("    - may_store");
        }
        if sem.is_pseudo {
            println!("    - is_pseudo");
        }
        if sem.has_unmodeled_side_effects {
            println!("    - has_unmodeled_side_effects");
        }
        println!("    - num_operands: {}", sem.num_operands);
        println!("    - num_defs: {}", sem.num_defs);
    } else {
        println!("  No semantic info available");
    }
    println!();
}

#[test]
fn test_semantic_info_extraction() {
    println!("=== Testing x86_64 Semantic Information ===\n");

    let nyxstone = Nyxstone::new("x86_64", NyxstoneConfig::default()).expect("Failed to create Nyxstone");

    // Test 1: JMP (unconditional branch, terminator)
    println!("Test 1: JMP instruction");
    let jmp_bytes = vec![0xeb, 0xfe]; // jmp $-2
    let jmp_result = nyxstone
        .disassemble_to_instructions(&jmp_bytes, 0x1000, 0)
        .expect("Failed to disassemble JMP");
    for insn in &jmp_result {
        print_semantic_info(insn);
        let sem = insn.semantics().expect("JMP should have semantic info");
        assert!(sem.is_branch, "JMP should be a branch");
        assert!(sem.is_unconditional_branch, "JMP should be unconditional");
        assert!(sem.is_terminator, "JMP should be a terminator");
        assert!(sem.is_barrier, "JMP should be a barrier");
    }

    // Test 2: CALL (call, branch)
    println!("Test 2: CALL instruction");
    let call_bytes = vec![0xe8, 0x00, 0x00, 0x00, 0x00]; // call $+5
    let call_result = nyxstone
        .disassemble_to_instructions(&call_bytes, 0x2000, 0)
        .expect("Failed to disassemble CALL");
    for insn in &call_result {
        print_semantic_info(insn);
        let sem = insn.semantics().expect("CALL should have semantic info");
        assert!(sem.is_call, "CALL should be marked as call");
    }

    // Test 3: RET (return, terminator)
    println!("Test 3: RET instruction");
    let ret_bytes = vec![0xc3]; // ret
    let ret_result = nyxstone
        .disassemble_to_instructions(&ret_bytes, 0x3000, 0)
        .expect("Failed to disassemble RET");
    for insn in &ret_result {
        print_semantic_info(insn);
        let sem = insn.semantics().expect("RET should have semantic info");
        assert!(sem.is_return, "RET should be marked as return");
        assert!(sem.is_terminator, "RET should be a terminator");
    }

    // Test 4: MOV (check via opcode_name)
    println!("Test 4: MOV instruction");
    let mov_bytes = vec![0x48, 0x89, 0xd8]; // mov rax, rbx
    let mov_result = nyxstone
        .disassemble_to_instructions(&mov_bytes, 0x4000, 0)
        .expect("Failed to disassemble MOV");
    for insn in &mov_result {
        print_semantic_info(insn);
        let sem = insn.semantics().expect("MOV should have semantic info");
        assert!(
            sem.opcode_name.starts_with("MOV"),
            "MOV opcode_name should start with MOV, got: {}",
            sem.opcode_name
        );
        assert_eq!(sem.num_defs, 1, "MOV should have 1 def");
    }

    // Test 5: PUSH (may_store)
    println!("Test 5: PUSH instruction");
    let push_bytes = vec![0x50]; // push rax
    let push_result = nyxstone
        .disassemble_to_instructions(&push_bytes, 0x5000, 0)
        .expect("Failed to disassemble PUSH");
    for insn in &push_result {
        print_semantic_info(insn);
        let sem = insn.semantics().expect("PUSH should have semantic info");
        assert!(sem.may_store, "PUSH should may_store");
    }

    // Test 6: POP (may_load)
    println!("Test 6: POP instruction");
    let pop_bytes = vec![0x58]; // pop rax
    let pop_result = nyxstone
        .disassemble_to_instructions(&pop_bytes, 0x6000, 0)
        .expect("Failed to disassemble POP");
    for insn in &pop_result {
        print_semantic_info(insn);
        let sem = insn.semantics().expect("POP should have semantic info");
        assert!(sem.may_load, "POP should may_load");
    }

    // Test 7: ADD (check via opcode_name)
    println!("Test 7: ADD instruction");
    let add_bytes = vec![0x48, 0x01, 0xd8]; // add rax, rbx
    let add_result = nyxstone
        .disassemble_to_instructions(&add_bytes, 0x7000, 0)
        .expect("Failed to disassemble ADD");
    for insn in &add_result {
        print_semantic_info(insn);
        let sem = insn.semantics().expect("ADD should have semantic info");
        assert!(
            sem.opcode_name.starts_with("ADD"),
            "ADD opcode_name should start with ADD, got: {}",
            sem.opcode_name
        );
    }

    // Test 8: CMP (check via opcode_name and flags)
    println!("Test 8: CMP instruction");
    let cmp_bytes = vec![0x48, 0x39, 0xd8]; // cmp rax, rbx
    let cmp_result = nyxstone
        .disassemble_to_instructions(&cmp_bytes, 0x8000, 0)
        .expect("Failed to disassemble CMP");
    for insn in &cmp_result {
        print_semantic_info(insn);
        let sem = insn.semantics().expect("CMP should have semantic info");
        assert!(
            sem.opcode_name.starts_with("CMP"),
            "CMP opcode_name should start with CMP, got: {}",
            sem.opcode_name
        );
        assert!(
            sem.flags & (1 << mcid_flags::COMPARE) != 0,
            "CMP should have COMPARE flag set"
        );
    }

    // Test 9: JE (conditional branch)
    println!("Test 9: JE (conditional branch) instruction");
    let je_bytes = vec![0x74, 0xfe]; // je $-2
    let je_result = nyxstone
        .disassemble_to_instructions(&je_bytes, 0x9000, 0)
        .expect("Failed to disassemble JE");
    for insn in &je_result {
        print_semantic_info(insn);
        let sem = insn.semantics().expect("JE should have semantic info");
        assert!(sem.is_branch, "JE should be a branch");
        assert!(sem.is_conditional_branch, "JE should be conditional");
        assert!(sem.is_terminator, "JE should be a terminator");
    }

    // Test 10: Assembly should NOT have semantic info
    println!("Test 10: Assembly should not have semantic info");
    let asm_result = nyxstone
        .assemble_to_instructions("mov rax, rbx", 0xa000)
        .expect("Failed to assemble");
    for insn in &asm_result {
        print_semantic_info(insn);
        assert!(
            insn.semantics().is_none(),
            "Assembly results should not have semantic info"
        );
    }

    println!("=== All tests passed! ===");
}
