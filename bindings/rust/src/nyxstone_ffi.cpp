#include "nyxstone_ffi.hpp"
#include "nyxstone/src/lib.rs.h" // CXX bridge generated types

#include <expected.hpp>

using namespace nyxstone;

// CXX bridge types are now defined in lib.rs.h

ByteResult NyxstoneFFI::assemble(
    const rust::str assembly, uint64_t address, const rust::Slice<const LabelDefinition> labels) const
{
    std::vector<Nyxstone::LabelDefinition> cpp_labels {};
    cpp_labels.reserve(labels.size());
    std::transform(std::begin(labels), std::end(labels), std::back_inserter(cpp_labels),
        [](const auto& label) { return Nyxstone::LabelDefinition { std::string(label.name), label.address }; });

    auto result = nyxstone->assemble(std::string { assembly }, address, cpp_labels).map([](const auto& cpp_bytes) {
        rust::Vec<uint8_t> bytes {};
        bytes.reserve(cpp_bytes.size());
        std::copy(cpp_bytes.begin(), cpp_bytes.end(), std::back_inserter(bytes));
        return bytes;
    });

    return ByteResult { result.value_or(rust::Vec<uint8_t> {}), result.error_or("") };
}

InstructionResult NyxstoneFFI::assemble_to_instructions(
    const rust::str assembly, uint64_t address, const rust::Slice<const LabelDefinition> labels) const
{
    std::vector<Nyxstone::LabelDefinition> cpp_labels;
    cpp_labels.reserve(labels.size());
    std::transform(std::begin(labels), std::end(labels), std::back_inserter(cpp_labels),
        [](const auto& label) { return Nyxstone::LabelDefinition { std::string(label.name), label.address }; });
    std::vector<Nyxstone::Instruction> cpp_instructions {};

    auto result = nyxstone->assemble_to_instructions(std::string { assembly }, address, cpp_labels)
                      .map([](const auto& cpp_instructions) {
                          rust::Vec<Instruction> instructions {};
                          instructions.reserve(cpp_instructions.size());
                          for (const auto& cpp_insn : cpp_instructions) {
                              rust::Vec<uint8_t> insn_bytes;
                              insn_bytes.reserve(cpp_insn.bytes.size());
                              std::copy(cpp_insn.bytes.begin(), cpp_insn.bytes.end(), std::back_inserter(insn_bytes));

                              // Assembly operations don't have semantic info
                              Instruction insn;
                              insn.address = cpp_insn.address;
                              insn.assembly = rust::String(cpp_insn.assembly);
                              insn.bytes = std::move(insn_bytes);
                              insn.has_semantic_info = false;
                              insn.semantic_info = SemanticInfo {}; // Default-constructed
                              instructions.push_back(std::move(insn));
                          }
                          return instructions;
                      });

    return InstructionResult { result.value_or(rust::Vec<Instruction> {}), result.error_or("") };
}

StringResult NyxstoneFFI::disassemble(const rust::Slice<const uint8_t> bytes, uint64_t address, size_t count) const
{
    std::vector<uint8_t> cpp_bytes;
    cpp_bytes.reserve(bytes.size());
    std::copy(bytes.begin(), bytes.end(), std::back_inserter(cpp_bytes));
    std::string cpp_disassembly;

    auto result = nyxstone->disassemble(cpp_bytes, address, count).map([](auto&& text) {
        return rust::String { std::move(text) };
    });

    return StringResult { result.value_or(rust::String {}), result.error_or("") };
}

InstructionResult NyxstoneFFI::disassemble_to_instructions(
    const rust::Slice<const uint8_t> bytes, uint64_t address, size_t count) const
{
    std::vector<uint8_t> cpp_bytes {};
    cpp_bytes.reserve(bytes.size());
    std::copy(bytes.begin(), bytes.end(), std::back_inserter(cpp_bytes));
    std::vector<Nyxstone::Instruction> cpp_instructions {};

    auto result
        = nyxstone->disassemble_to_instructions(cpp_bytes, address, count).map([](const auto& cpp_instructions) {
              rust::Vec<Instruction> instructions {};
              for (const auto& cpp_insn : cpp_instructions) {
                  rust::Vec<uint8_t> insn_bytes;
                  insn_bytes.reserve(cpp_insn.bytes.size());
                  std::copy(cpp_insn.bytes.begin(), cpp_insn.bytes.end(), std::back_inserter(insn_bytes));

                  // Convert semantic info if present
                  bool has_semantic = cpp_insn.semantic_info.has_value();
                  SemanticInfo semantic_info {};
                  if (has_semantic) {
                      const auto& si = cpp_insn.semantic_info.value();
                      semantic_info.opcode_name = rust::String(si.opcode_name);
                      semantic_info.flags = si.flags;
                      semantic_info.target_flags = si.target_flags;
                      semantic_info.is_branch = si.is_branch;
                      semantic_info.is_call = si.is_call;
                      semantic_info.is_return = si.is_return;
                      semantic_info.is_conditional_branch = si.is_conditional_branch;
                      semantic_info.is_unconditional_branch = si.is_unconditional_branch;
                      semantic_info.is_indirect_branch = si.is_indirect_branch;
                      semantic_info.is_terminator = si.is_terminator;
                      semantic_info.is_barrier = si.is_barrier;
                      semantic_info.may_load = si.may_load;
                      semantic_info.may_store = si.may_store;
                      semantic_info.is_pseudo = si.is_pseudo;
                      semantic_info.has_unmodeled_side_effects = si.has_unmodeled_side_effects;
                      semantic_info.num_operands = si.num_operands;
                      semantic_info.num_defs = si.num_defs;
                  }

                  Instruction insn;
                  insn.address = cpp_insn.address;
                  insn.assembly = rust::String(cpp_insn.assembly);
                  insn.bytes = std::move(insn_bytes);
                  insn.has_semantic_info = has_semantic;
                  insn.semantic_info = semantic_info;
                  instructions.push_back(std::move(insn));
              }
              return instructions;
          });

    return InstructionResult { result.value_or(rust::Vec<Instruction> {}), result.error_or("") };
}

NyxstoneResult create_nyxstone_ffi( // cppcheck-suppress unusedFunction
    const rust::str triple_name, const rust::str cpu, const rust::str features, const IntegerBase imm_style)
{
    NyxstoneBuilder::IntegerBase style = static_cast<NyxstoneBuilder::IntegerBase>(static_cast<uint8_t>(imm_style));

    auto result = NyxstoneBuilder(std::string { triple_name })
                      .with_cpu(std::string { cpu })
                      .with_features(std::string { features })
                      .with_immediate_style(style)
                      .build();

    // Note: This is disgusting, but this is necesarry for two reasons:
    //       1. We can not return any kind of variant to Rust, thus need to have some kind of emtpy nyxstone
    //          instance if the function failed.
    //       2. The value_or() function can't be used in combination with a unique_ptr, since it is not
    //          copy-constructable.
    auto maybe_ffi = bool(result) ? std::make_unique<NyxstoneFFI>(std::move(result.value()))
                                  : std::unique_ptr<NyxstoneFFI>(nullptr);

    return NyxstoneResult { std::move(maybe_ffi), result.error_or("") };
}
