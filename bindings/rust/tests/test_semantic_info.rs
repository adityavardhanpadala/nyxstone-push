use nyxstone::{Nyxstone, NyxstoneConfig};

fn print_semantic_info(insn: &nyxstone::Instruction) {
    println!("Instruction: {} @ {:#x}", insn.assembly, insn.address);
    print!("  Bytes: ");
    for byte in &insn.bytes {
        print!("{:02x} ", byte);
    }
    println!();

    if insn.has_semantic_info {
        let sem = &insn.semantic_info;
        println!("  Semantic Info:");
        if sem.is_branch { println!("    - is_branch"); }
        if sem.is_call { println!("    - is_call"); }
        if sem.is_return { println!("    - is_return"); }
        if sem.is_conditional_branch { println!("    - is_conditional_branch"); }
        if sem.is_unconditional_branch { println!("    - is_unconditional_branch"); }
        if sem.is_indirect_branch { println!("    - is_indirect_branch"); }
        if sem.is_terminator { println!("    - is_terminator"); }
        if sem.is_barrier { println!("    - is_barrier"); }
        if sem.may_load { println!("    - may_load"); }
        if sem.may_store { println!("    - may_store"); }
        if sem.can_fold_as_load { println!("    - can_fold_as_load"); }
        if sem.is_add { println!("    - is_add"); }
        if sem.is_compare { println!("    - is_compare"); }
        if sem.is_move_reg { println!("    - is_move_reg"); }
        if sem.is_move_immediate { println!("    - is_move_immediate"); }
        if sem.is_trap { println!("    - is_trap"); }
        if sem.is_pseudo { println!("    - is_pseudo"); }
        if sem.has_unmodeled_side_effects { println!("    - has_unmodeled_side_effects"); }
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

    let nyxstone = Nyxstone::new("x86_64", NyxstoneConfig::default())
        .expect("Failed to create Nyxstone");

    // Test 1: JMP (unconditional branch, terminator)
    println!("Test 1: JMP instruction");
    let jmp_bytes = vec![0xeb, 0xfe];  // jmp $-2
    let jmp_result = nyxstone.disassemble_to_instructions(&jmp_bytes, 0x1000, 0)
        .expect("Failed to disassemble JMP");
    for insn in &jmp_result {
        print_semantic_info(insn);
        assert!(insn.has_semantic_info, "JMP should have semantic info");
        assert!(insn.semantic_info.is_branch, "JMP should be a branch");
        assert!(insn.semantic_info.is_unconditional_branch, "JMP should be unconditional");
        assert!(insn.semantic_info.is_terminator, "JMP should be a terminator");
        assert!(insn.semantic_info.is_barrier, "JMP should be a barrier");
    }

    // Test 2: CALL (call, branch)
    println!("Test 2: CALL instruction");
    let call_bytes = vec![0xe8, 0x00, 0x00, 0x00, 0x00];  // call $+5
    let call_result = nyxstone.disassemble_to_instructions(&call_bytes, 0x2000, 0)
        .expect("Failed to disassemble CALL");
    for insn in &call_result {
        print_semantic_info(insn);
        assert!(insn.has_semantic_info, "CALL should have semantic info");
        assert!(insn.semantic_info.is_call, "CALL should be marked as call");
    }

    // Test 3: RET (return, terminator)
    println!("Test 3: RET instruction");
    let ret_bytes = vec![0xc3];  // ret
    let ret_result = nyxstone.disassemble_to_instructions(&ret_bytes, 0x3000, 0)
        .expect("Failed to disassemble RET");
    for insn in &ret_result {
        print_semantic_info(insn);
        assert!(insn.has_semantic_info, "RET should have semantic info");
        assert!(insn.semantic_info.is_return, "RET should be marked as return");
        assert!(insn.semantic_info.is_terminator, "RET should be a terminator");
    }

    // Test 4: MOV (move register)
    println!("Test 4: MOV instruction");
    let mov_bytes = vec![0x48, 0x89, 0xd8];  // mov rax, rbx
    let mov_result = nyxstone.disassemble_to_instructions(&mov_bytes, 0x4000, 0)
        .expect("Failed to disassemble MOV");
    for insn in &mov_result {
        print_semantic_info(insn);
        assert!(insn.has_semantic_info, "MOV should have semantic info");
        assert!(insn.semantic_info.is_move_reg, "MOV should be marked as move_reg");
        assert_eq!(insn.semantic_info.num_defs, 1, "MOV should have 1 def");
    }

    // Test 5: PUSH (may_store)
    println!("Test 5: PUSH instruction");
    let push_bytes = vec![0x50];  // push rax
    let push_result = nyxstone.disassemble_to_instructions(&push_bytes, 0x5000, 0)
        .expect("Failed to disassemble PUSH");
    for insn in &push_result {
        print_semantic_info(insn);
        assert!(insn.has_semantic_info, "PUSH should have semantic info");
        assert!(insn.semantic_info.may_store, "PUSH should may_store");
    }

    // Test 6: POP (may_load)
    println!("Test 6: POP instruction");
    let pop_bytes = vec![0x58];  // pop rax
    let pop_result = nyxstone.disassemble_to_instructions(&pop_bytes, 0x6000, 0)
        .expect("Failed to disassemble POP");
    for insn in &pop_result {
        print_semantic_info(insn);
        assert!(insn.has_semantic_info, "POP should have semantic info");
        assert!(insn.semantic_info.may_load, "POP should may_load");
    }

    // Test 7: CMP (is_compare)
    println!("Test 7: CMP instruction");
    let cmp_bytes = vec![0x48, 0x39, 0xd8];  // cmp rax, rbx
    let cmp_result = nyxstone.disassemble_to_instructions(&cmp_bytes, 0x8000, 0)
        .expect("Failed to disassemble CMP");
    for insn in &cmp_result {
        print_semantic_info(insn);
        assert!(insn.has_semantic_info, "CMP should have semantic info");
        assert!(insn.semantic_info.is_compare, "CMP should be marked as compare");
    }

    // Test 8: JE (conditional branch)
    println!("Test 8: JE (conditional branch) instruction");
    let je_bytes = vec![0x74, 0xfe];  // je $-2
    let je_result = nyxstone.disassemble_to_instructions(&je_bytes, 0x9000, 0)
        .expect("Failed to disassemble JE");
    for insn in &je_result {
        print_semantic_info(insn);
        assert!(insn.has_semantic_info, "JE should have semantic info");
        assert!(insn.semantic_info.is_branch, "JE should be a branch");
        assert!(insn.semantic_info.is_conditional_branch, "JE should be conditional");
        assert!(insn.semantic_info.is_terminator, "JE should be a terminator");
    }

    // Test 9: Assembly should NOT have semantic info
    println!("Test 9: Assembly should not have semantic info");
    let asm_result = nyxstone.assemble_to_instructions("mov rax, rbx", 0xa000)
        .expect("Failed to assemble");
    for insn in &asm_result {
        print_semantic_info(insn);
        assert!(!insn.has_semantic_info, "Assembly results should not have semantic info");
    }

    println!("=== All tests passed! ===");
}
