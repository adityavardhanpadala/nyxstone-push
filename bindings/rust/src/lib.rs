use anyhow::anyhow;
use ffi::create_nyxstone_ffi;
use ffi::LabelDefinition;

// Re-export Instruction and SemanticInfo
pub use crate::ffi::Instruction;
pub use crate::ffi::SemanticInfo;

/// Public interface for calling nyxstone from rust.
/// # Examples
///
/// ```rust
/// # use std::collections::HashMap;
/// # use nyxstone::{Nyxstone, NyxstoneConfig, Instruction, SemanticInfo};
/// # fn main() -> anyhow::Result<()> {
/// let nyxstone = Nyxstone::new("x86_64", NyxstoneConfig::default())?;
///
/// let instructions = nyxstone.assemble_to_instructions("mov rax, rbx", 0x1000)?;
///
/// assert_eq!(
///      instructions,
///      vec![Instruction {
///          address: 0x1000,
///          assembly: "mov rax, rbx".into(),
///          bytes: vec![0x48, 0x89, 0xd8],
///          has_semantic_info: false,
///          semantic_info: SemanticInfo::default(),
///      }]
/// );
/// # Ok(())
/// # }
/// ```
pub struct Nyxstone {
    /// The c++ `unique_ptr` holding the actual `NyxstoneFFI` instance.
    inner: cxx::UniquePtr<ffi::NyxstoneFFI>,
}

/// Configuration options for the integer style of immediates in disassembly output.
#[derive(Debug, PartialEq, Eq, Default, Clone, Copy)]
pub enum IntegerBase {
    /// Immediates are represented in decimal format.
    #[default]
    Dec = 0,
    /// Immediates are represented in hex format, prepended with 0x, for example: 0xff.
    HexPrefix = 1,
    /// Immediates are represented in hex format, suffixed with h, for example: 0ffh.
    HexSuffix = 2,
}

impl From<IntegerBase> for ffi::IntegerBase {
    fn from(val: IntegerBase) -> Self {
        match val {
            IntegerBase::Dec => ffi::IntegerBase::Dec,
            IntegerBase::HexPrefix => ffi::IntegerBase::HexPrefix,
            IntegerBase::HexSuffix => ffi::IntegerBase::HexSuffix,
        }
    }
}

impl<'name> LabelDefinition<'name> {
    fn new(name: &'name str, address: u64) -> Self {
        LabelDefinition { name, address }
    }
}

impl<'a, S: 'a> From<(&'a S, &u64)> for LabelDefinition<'a>
where
    S: AsRef<str>,
{
    fn from(value: (&'a S, &u64)) -> Self {
        LabelDefinition::new(value.0.as_ref(), *value.1)
    }
}

impl Nyxstone {
    /// Builds a Nyxstone instance with specific configuration.
    ///
    /// # Parameters:
    /// - `target_triple`: Llvm target triple or architecture identifier of triple.
    /// - `config`: Optional configuration for the `Nyxstone` instance.
    ///
    /// # Note
    ///  For the most common architectures, we recommend the following triples:
    ///  - x86_32: `i686-linux-gnu`
    ///  - x86_64: `x86_64-linux-gnu`
    ///  - armv6m: `armv6m-none-eabi`
    ///  - armv7m: `armv7m-none-eabi`
    ///  - armv8m: `armv8m.main-none-eabi`
    ///  - aarch64: `aarch64-linux-gnueabihf`
    ///    Using shorthand identifiers like `arm` can lead to Nyxstone not being able to assemble certain instructions.
    ///
    /// # Returns
    /// Ok() and the Nyxstone instance on success, Err() otherwise.
    ///
    /// # Errors
    /// Errors occur when the LLVM triple was not supplied to the builder or LLVM fails.
    pub fn new(target_triple: &str, config: NyxstoneConfig) -> anyhow::Result<Nyxstone> {
        let result = create_nyxstone_ffi(
            target_triple,
            config.cpu,
            config.features,
            config.immediate_style.into(),
        );

        if !result.error.is_empty() {
            return Err(anyhow!("{}", result.error));
        }

        Ok(Nyxstone { inner: result.ok })
    }

    /// Translates assembly instructions at a given start address to bytes.
    ///
    /// # Note:
    /// Does not support assembly directives that impact the layout (f. i., .section, .org).
    ///
    /// # Parameters:
    /// - `assembly`: The instructions to assemble.
    /// - `address`: The start location of the instructions.
    ///
    /// # Returns:
    /// Ok() and bytecode on success, Err() otherwise.
    pub fn assemble(&self, assembly: &str, address: u64) -> anyhow::Result<Vec<u8>> {
        let byte_result = self.inner.assemble(assembly, address, &Vec::new());

        if !byte_result.error.is_empty() {
            return Err(anyhow!(
                "Error during assemble (= '{assembly}' at {address}): {}.",
                byte_result.error
            ));
        }

        Ok(byte_result.ok)
    }

    /// Translates assembly instructions at a given start address to bytes, with additional label definitions.
    ///
    /// # Note:
    /// Does not support assembly directives that impact the layout (f. i., .section, .org).
    ///
    /// # Parameters:
    /// - `assembly`: The instructions to assemble.
    /// - `address`: The start location of the instructions.
    /// - `labels`: Additional label definitions by absolute address, expects a reference to some `Map<AsRef<str>, u64>`
    ///   which can be iterated over.
    ///
    /// # Returns:
    /// Ok() and bytecode on success, Err() otherwise.
    pub fn assemble_with<'iter, It, Lbl>(&self, assembly: &str, address: u64, labels: It) -> anyhow::Result<Vec<u8>>
    where
        Lbl: 'iter + AsRef<str>,
        It: IntoIterator<Item = (&'iter Lbl, &'iter u64)>,
    {
        let labels: Vec<LabelDefinition> = labels.into_iter().map(LabelDefinition::from).collect();

        let byte_result = self.inner.assemble(assembly, address, &labels);

        if !byte_result.error.is_empty() {
            return Err(anyhow!(
                "Error during assemble (= '{assembly}' at {address}): {}.",
                byte_result.error
            ));
        }

        Ok(byte_result.ok)
    }

    /// Translates assembly instructions at a given start address to instruction details containing bytes.
    ///
    /// # Note:
    /// Does not support assembly directives that impact the layout (f. i., .section, .org).
    ///
    /// # Parameters:
    /// - `assembly`: The instructions to assemble.
    /// - `address`: The start location of the instructions.
    ///
    /// # Returns:
    /// Ok() and instruction details on success, Err() otherwise.
    pub fn assemble_to_instructions(&self, assembly: &str, address: u64) -> anyhow::Result<Vec<Instruction>> {
        let instr_result = self.inner.assemble_to_instructions(assembly, address, &Vec::new());

        if !instr_result.error.is_empty() {
            return Err(anyhow!("Error during disassembly: {}.", instr_result.error));
        }

        Ok(instr_result.ok)
    }

    /// Translates assembly instructions at a given start address to instruction details containing bytes, with
    /// additional label definitions.
    ///
    /// # Note:
    /// Does not support assembly directives that impact the layout (f. i., .section, .org).
    ///
    /// # Parameters:
    /// - `assembly`: The instructions to assemble.
    /// - `address`: The start location of the instructions.
    /// - `labels`: Additional label definitions by absolute address, expects a reference to some `Map<AsRef<str>, u64>` which can be iterated over.
    ///
    /// # Returns:
    /// Ok() and instruction details on success, Err() otherwise.
    pub fn assemble_to_instructions_with<'iter, It, Lbl>(
        &self,
        assembly: &str,
        address: u64,
        labels: It,
    ) -> anyhow::Result<Vec<Instruction>>
    where
        Lbl: 'iter + AsRef<str>,
        It: IntoIterator<Item = (&'iter Lbl, &'iter u64)>,
    {
        let labels: Vec<LabelDefinition> = labels.into_iter().map(LabelDefinition::from).collect();

        let instr_result = self.inner.assemble_to_instructions(assembly, address, &labels);

        if !instr_result.error.is_empty() {
            return Err(anyhow!("Error during disassembly: {}.", instr_result.error));
        }

        Ok(instr_result.ok)
    }

    /// Translates bytes to disassembly text at a given start address.
    ///
    /// # Parameters:
    /// - `bytes`: The bytes to be disassembled.
    /// - `address`: The start address of the bytes.
    /// - `count`: Number of instructions to be disassembled. If zero is supplied, all instructions are disassembled.
    ///
    /// # Returns:
    /// Ok() and disassembly text on success, Err() otherwise.
    pub fn disassemble(&self, bytes: &[u8], address: u64, count: usize) -> anyhow::Result<String> {
        let text_result = self.inner.disassemble(bytes, address, count);

        if !text_result.error.is_empty() {
            return Err(anyhow!("Error during disassembly: {}.", text_result.error));
        }

        Ok(text_result.ok)
    }

    /// Translates bytes to instruction details containing disassembly text at a given start address.
    ///
    /// # Parameters:
    /// - `bytes`: The bytes to be disassembled.
    /// - `address`: The start address of the bytes.
    /// - `count`: Number of instructions to be disassembled. If zero is supplied, all instructions are disassembled.
    ///
    /// # Returns:
    /// Ok() and Instruction details on success, Err() otherwise.
    pub fn disassemble_to_instructions(
        &self,
        bytes: &[u8],
        address: u64,
        count: usize,
    ) -> anyhow::Result<Vec<Instruction>> {
        let instr_result = self.inner.disassemble_to_instructions(bytes, address, count);

        if !instr_result.error.is_empty() {
            return Err(anyhow!("Error during disassembly: {}.", instr_result.error));
        }

        Ok(instr_result.ok)
    }
}

unsafe impl Send for Nyxstone {}

/// Initialization configuration for Nyxstone
#[derive(Debug, Default)]
pub struct NyxstoneConfig<'a, 'b> {
    /// The LLVM cpu identifier, empty for no specific cpu target.
    pub cpu: &'a str,
    /// An LLVM feature string, features are comma seperated strings, which are prepended with '+' when enabled and '-' if disabled.
    pub features: &'b str,
    /// The printing style of immediates.
    pub immediate_style: IntegerBase,
}

#[cxx::bridge]
mod ffi {
    /// Defines the location of a label by absolute address.
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub struct LabelDefinition<'name> {
        /// Name of the label.
        pub name: &'name str,
        /// Absolute address of the label.
        pub address: u64,
    }

    /// Semantic information about an instruction (from LLVM MCInstrDesc).
    /// Only available when disassembling.
    ///
    /// Named fields are provided for reliable structural properties (control flow,
    /// memory operations). For instruction classification, use `opcode_name` for
    /// precise identification or `flags`/`target_flags` for raw MCInstrDesc access.
    /// Use the `mcid_flags` module constants to test individual bits in `flags`.
    #[derive(Clone, Debug, PartialEq, Eq, Default)]
    pub struct SemanticInfo {
        /// LLVM opcode name (e.g. "ADD64rr", "MOV64rr", "JMP_1")
        pub opcode_name: String,

        /// Raw MCInstrDesc flags bitmask (MCID::Flag enum values)
        pub flags: u64,
        /// Target-specific flags from MCInstrDesc::TSFlags
        pub target_flags: u64,

        // Control flow properties
        pub is_branch: bool,
        pub is_call: bool,
        pub is_return: bool,
        pub is_conditional_branch: bool,
        pub is_unconditional_branch: bool,
        pub is_indirect_branch: bool,
        pub is_terminator: bool,
        pub is_barrier: bool,

        // Memory operations
        pub may_load: bool,
        pub may_store: bool,

        // Instruction classification
        pub is_pseudo: bool,

        // Other properties
        pub has_unmodeled_side_effects: bool,
        pub num_operands: u16,
        pub num_defs: u16,
    }

    /// Instruction details
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub struct Instruction {
        /// Absolute address of the instruction.
        pub address: u64,
        /// Assembly string representing the instruction.
        pub assembly: String,
        /// Byte code of the instruction.
        pub bytes: Vec<u8>,
        /// Flag indicating if semantic_info is valid (only true for disassembly)
        pub has_semantic_info: bool,
        /// Semantic information (only valid when has_semantic_info is true)
        pub semantic_info: SemanticInfo,
    }

    pub struct ByteResult {
        pub ok: Vec<u8>,
        pub error: String,
    }

    pub struct InstructionResult {
        pub ok: Vec<Instruction>,
        pub error: String,
    }

    pub struct StringResult {
        pub ok: String,
        pub error: String,
    }

    pub struct NyxstoneResult {
        pub ok: UniquePtr<NyxstoneFFI>,
        pub error: String,
    }

    /// Configuration options for the integer style of immediates in disassembly output.
    pub enum IntegerBase {
        /// Immediates are represented in decimal format.
        Dec = 0,
        /// Immediates are represented in hex format, prepended with 0x, for example: 0xff.
        HexPrefix = 1,
        /// Immediates are represented in hex format, suffixed with h, for example: 0ffh.
        HexSuffix = 2,
    }

    unsafe extern "C++" {
        include!("nyxstone/src/nyxstone_ffi.hpp");

        type NyxstoneFFI;

        /// Constructs a Nyxstone instance for the architecture and cpu specified by the llvm-style target triple and
        /// cpu. Also allows enabling and disabling features via the `features` string.
        /// Features are comma-seperated feature strings, which start with a plus if they should be enabled and a minus
        /// if they should be disabled.
        /// Params:
        /// - triple_name: The llvm triple.
        /// - cpu: The cpu to be used, can be empty
        /// - features: llvm features string (features delimited by `,` with `+` for enable and `-` for disable), can be empty
        /// # Returns
        /// Ok() and UniquePtr holding a NyxstoneFFI on success, Err() otherwise.
        fn create_nyxstone_ffi(triple_name: &str, cpu: &str, features: &str, style: IntegerBase) -> NyxstoneResult;

        // Translates assembly instructions at a given start address to bytes.
        // Additional label definitions by absolute address may be supplied.
        // Does not support assembly directives that impact the layout (f. i., .section, .org).
        fn assemble(self: &NyxstoneFFI, assembly: &str, address: u64, labels: &[LabelDefinition]) -> ByteResult;

        // Translates assembly instructions at a given start address to instruction details containing bytes.
        // Additional label definitions by absolute address may be supplied.
        // Does not support assembly directives that impact the layout (f. i., .section, .org).
        fn assemble_to_instructions(
            self: &NyxstoneFFI,
            assembly: &str,
            address: u64,
            labels: &[LabelDefinition],
        ) -> InstructionResult;

        // Translates bytes to disassembly text at given start address.
        fn disassemble(self: &NyxstoneFFI, bytes: &[u8], address: u64, count: usize) -> StringResult;

        // Translates bytes to instruction details containing disassembly text at a given start address.
        fn disassemble_to_instructions(
            self: &NyxstoneFFI,
            bytes: &[u8],
            address: u64,
            count: usize,
        ) -> InstructionResult;
    }
}

unsafe impl Send for ffi::NyxstoneFFI {}

impl ffi::Instruction {
    /// Returns the semantic information for this instruction, if available.
    /// Semantic info is only populated for disassembled instructions, not assembled ones.
    pub fn semantics(&self) -> Option<&ffi::SemanticInfo> {
        if self.has_semantic_info {
            Some(&self.semantic_info)
        } else {
            None
        }
    }
}

/// Bit positions for MCID::Flag values from LLVM 18 MCInstrDesc.h.
///
/// Use these constants to test individual bits in `SemanticInfo::flags`:
/// ```ignore
/// use nyxstone::mcid_flags;
/// if sem.flags & (1 << mcid_flags::COMPARE) != 0 {
///     // instruction is a compare
/// }
/// ```
pub mod mcid_flags {
    pub const PRE_ISEL_OPCODE: u32 = 0;
    pub const VARIADIC: u32 = 1;
    pub const HAS_OPTIONAL_DEF: u32 = 2;
    pub const PSEUDO: u32 = 3;
    pub const META: u32 = 4;
    pub const RETURN: u32 = 5;
    pub const EH_SCOPE_RETURN: u32 = 6;
    pub const CALL: u32 = 7;
    pub const BARRIER: u32 = 8;
    pub const TERMINATOR: u32 = 9;
    pub const BRANCH: u32 = 10;
    pub const INDIRECT_BRANCH: u32 = 11;
    pub const COMPARE: u32 = 12;
    pub const MOVE_IMM: u32 = 13;
    pub const MOVE_REG: u32 = 14;
    pub const BITCAST: u32 = 15;
    pub const SELECT: u32 = 16;
    pub const DELAY_SLOT: u32 = 17;
    pub const FOLDABLE_AS_LOAD: u32 = 18;
    pub const MAY_LOAD: u32 = 19;
    pub const MAY_STORE: u32 = 20;
    pub const MAY_RAISE_FP_EXCEPTION: u32 = 21;
    pub const PREDICABLE: u32 = 22;
    pub const NOT_DUPLICABLE: u32 = 23;
    pub const UNMODELED_SIDE_EFFECTS: u32 = 24;
    pub const COMMUTABLE: u32 = 25;
    pub const CONVERTIBLE_TO_3_ADDR: u32 = 26;
    pub const USES_CUSTOM_INSERTER: u32 = 27;
    pub const HAS_POST_ISEL_HOOK: u32 = 28;
    pub const REMATERIALIZABLE: u32 = 29;
    pub const CHEAP_AS_A_MOVE: u32 = 30;
    pub const EXTRA_SRC_REG_ALLOC_REQ: u32 = 31;
    pub const EXTRA_DEF_REG_ALLOC_REQ: u32 = 32;
    pub const REG_SEQUENCE: u32 = 33;
    pub const EXTRACT_SUBREG: u32 = 34;
    pub const INSERT_SUBREG: u32 = 35;
    pub const CONVERGENT: u32 = 36;
    pub const ADD: u32 = 37;
    pub const TRAP: u32 = 38;
    pub const VARIADIC_OPS_ARE_DEFS: u32 = 39;
    pub const AUTHENTICATED: u32 = 40;
}
