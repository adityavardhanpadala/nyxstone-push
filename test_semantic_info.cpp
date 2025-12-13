#include "nyxstone.h"
#include <iostream>
#include <iomanip>

void print_semantic_info(const nyxstone::Nyxstone::Instruction& insn) {
    std::cout << "Instruction: " << insn.assembly << " @ 0x" << std::hex << insn.address << std::dec << "\n";
    std::cout << "  Bytes: ";
    for (auto byte : insn.bytes) {
        std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)byte << " ";
    }
    std::cout << std::dec << "\n";

    if (insn.semantic_info.has_value()) {
        const auto& sem = insn.semantic_info.value();
        std::cout << "  Semantic Info:\n";
        if (sem.is_branch) std::cout << "    - is_branch\n";
        if (sem.is_call) std::cout << "    - is_call\n";
        if (sem.is_return) std::cout << "    - is_return\n";
        if (sem.is_conditional_branch) std::cout << "    - is_conditional_branch\n";
        if (sem.is_unconditional_branch) std::cout << "    - is_unconditional_branch\n";
        if (sem.is_indirect_branch) std::cout << "    - is_indirect_branch\n";
        if (sem.is_terminator) std::cout << "    - is_terminator\n";
        if (sem.is_barrier) std::cout << "    - is_barrier\n";
        if (sem.may_load) std::cout << "    - may_load\n";
        if (sem.may_store) std::cout << "    - may_store\n";
        if (sem.can_fold_as_load) std::cout << "    - can_fold_as_load\n";
        if (sem.is_add) std::cout << "    - is_add\n";
        if (sem.is_compare) std::cout << "    - is_compare\n";
        if (sem.is_move_reg) std::cout << "    - is_move_reg\n";
        if (sem.is_move_immediate) std::cout << "    - is_move_immediate\n";
        if (sem.is_trap) std::cout << "    - is_trap\n";
        if (sem.is_pseudo) std::cout << "    - is_pseudo\n";
        if (sem.has_unmodeled_side_effects) std::cout << "    - has_unmodeled_side_effects\n";
        std::cout << "    - num_operands: " << sem.num_operands << "\n";
        std::cout << "    - num_defs: " << sem.num_defs << "\n";
    } else {
        std::cout << "  No semantic info available\n";
    }
    std::cout << "\n";
}

int main() {
    // Build Nyxstone for x86_64
    auto nyxstone_result = nyxstone::NyxstoneBuilder("x86_64").build();
    if (!nyxstone_result.has_value()) {
        std::cerr << "Failed to create Nyxstone: " << nyxstone_result.error() << "\n";
        return 1;
    }
    auto nyxstone = std::move(nyxstone_result.value());

    std::cout << "=== Testing x86_64 Semantic Information ===\n\n";

    // Test 1: JMP (unconditional branch, terminator)
    std::cout << "Test 1: JMP instruction\n";
    std::vector<uint8_t> jmp_bytes = {0xeb, 0xfe};  // jmp $-2
    auto jmp_result = nyxstone->disassemble_to_instructions(jmp_bytes, 0x1000, 0);
    if (jmp_result.has_value()) {
        for (const auto& insn : jmp_result.value()) {
            print_semantic_info(insn);
        }
    }

    // Test 2: CALL (call, branch)
    std::cout << "Test 2: CALL instruction\n";
    std::vector<uint8_t> call_bytes = {0xe8, 0x00, 0x00, 0x00, 0x00};  // call $+5
    auto call_result = nyxstone->disassemble_to_instructions(call_bytes, 0x2000, 0);
    if (call_result.has_value()) {
        for (const auto& insn : call_result.value()) {
            print_semantic_info(insn);
        }
    }

    // Test 3: RET (return, terminator)
    std::cout << "Test 3: RET instruction\n";
    std::vector<uint8_t> ret_bytes = {0xc3};  // ret
    auto ret_result = nyxstone->disassemble_to_instructions(ret_bytes, 0x3000, 0);
    if (ret_result.has_value()) {
        for (const auto& insn : ret_result.value()) {
            print_semantic_info(insn);
        }
    }

    // Test 4: MOV (move register)
    std::cout << "Test 4: MOV instruction\n";
    std::vector<uint8_t> mov_bytes = {0x48, 0x89, 0xd8};  // mov rax, rbx
    auto mov_result = nyxstone->disassemble_to_instructions(mov_bytes, 0x4000, 0);
    if (mov_result.has_value()) {
        for (const auto& insn : mov_result.value()) {
            print_semantic_info(insn);
        }
    }

    // Test 5: PUSH (may_store)
    std::cout << "Test 5: PUSH instruction\n";
    std::vector<uint8_t> push_bytes = {0x50};  // push rax
    auto push_result = nyxstone->disassemble_to_instructions(push_bytes, 0x5000, 0);
    if (push_result.has_value()) {
        for (const auto& insn : push_result.value()) {
            print_semantic_info(insn);
        }
    }

    // Test 6: POP (may_load)
    std::cout << "Test 6: POP instruction\n";
    std::vector<uint8_t> pop_bytes = {0x58};  // pop rax
    auto pop_result = nyxstone->disassemble_to_instructions(pop_bytes, 0x6000, 0);
    if (pop_result.has_value()) {
        for (const auto& insn : pop_result.value()) {
            print_semantic_info(insn);
        }
    }

    // Test 7: ADD (is_add)
    std::cout << "Test 7: ADD instruction\n";
    std::vector<uint8_t> add_bytes = {0x48, 0x01, 0xd8};  // add rax, rbx
    auto add_result = nyxstone->disassemble_to_instructions(add_bytes, 0x7000, 0);
    if (add_result.has_value()) {
        for (const auto& insn : add_result.value()) {
            print_semantic_info(insn);
        }
    }

    // Test 8: CMP (is_compare)
    std::cout << "Test 8: CMP instruction\n";
    std::vector<uint8_t> cmp_bytes = {0x48, 0x39, 0xd8};  // cmp rax, rbx
    auto cmp_result = nyxstone->disassemble_to_instructions(cmp_bytes, 0x8000, 0);
    if (cmp_result.has_value()) {
        for (const auto& insn : cmp_result.value()) {
            print_semantic_info(insn);
        }
    }

    // Test 9: JE (conditional branch)
    std::cout << "Test 9: JE (conditional branch) instruction\n";
    std::vector<uint8_t> je_bytes = {0x74, 0xfe};  // je $-2
    auto je_result = nyxstone->disassemble_to_instructions(je_bytes, 0x9000, 0);
    if (je_result.has_value()) {
        for (const auto& insn : je_result.value()) {
            print_semantic_info(insn);
        }
    }

    std::cout << "=== All tests completed ===\n";
    return 0;
}
