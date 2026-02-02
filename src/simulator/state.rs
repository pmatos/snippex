use crate::error::{Error, Result};
use crate::simulator::TargetArch;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

const OUTPUT_BUFFER_SIZE: usize = 4096;
const REGISTER_SECTION_SIZE: usize = 128; // 64-bit: 16 regs × 8 bytes
const FLAGS_SECTION_SIZE: usize = 8;
const MEMORY_SECTION_OFFSET: usize = 256;

// 32-bit layout constants
const FLAGS_OFFSET_32: usize = 32;
const FLAGS_SIZE_32: usize = 4;
const MEMORY_SECTION_OFFSET_32: usize = 64;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InitialState {
    pub registers: HashMap<String, u64>,
    pub memory_locations: HashMap<u64, Vec<u8>>,
    pub stack_setup: Vec<u64>,
}

impl Default for InitialState {
    fn default() -> Self {
        Self::new()
    }
}

impl InitialState {
    pub fn new() -> Self {
        Self {
            registers: HashMap::new(),
            memory_locations: HashMap::new(),
            stack_setup: Vec::new(),
        }
    }

    pub fn set_register(&mut self, name: &str, value: u64) {
        self.registers.insert(name.to_string(), value);
    }

    pub fn set_memory(&mut self, address: u64, data: Vec<u8>) {
        self.memory_locations.insert(address, data);
    }

    pub fn add_stack_value(&mut self, value: u64) {
        self.stack_setup.push(value);
    }

    #[allow(dead_code)]
    pub fn get_register(&self, name: &str) -> Option<u64> {
        self.registers.get(name).copied()
    }

    #[allow(dead_code)]
    pub fn get_memory(&self, address: u64) -> Option<&Vec<u8>> {
        self.memory_locations.get(&address)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FinalState {
    pub registers: HashMap<String, u64>,
    pub flags: u64,
    pub memory_locations: HashMap<u64, Vec<u8>>,
}

impl Default for FinalState {
    fn default() -> Self {
        Self::new()
    }
}

impl FinalState {
    pub fn new() -> Self {
        Self {
            registers: HashMap::new(),
            flags: 0,
            memory_locations: HashMap::new(),
        }
    }

    pub fn parse_from_output_for_arch(output: &[u8], arch: TargetArch) -> Result<Self> {
        if arch.is_32bit() {
            return Self::parse_from_output_32(output);
        }
        Self::parse_from_output(output)
    }

    fn parse_from_output_32(output: &[u8]) -> Result<Self> {
        if output.len() < OUTPUT_BUFFER_SIZE {
            return Err(Error::Simulation(format!(
                "Output buffer too small: {} bytes, expected at least {} bytes",
                output.len(),
                OUTPUT_BUFFER_SIZE
            )));
        }

        let mut state = FinalState::new();

        let register_names = ["eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp"];

        for (i, &name) in register_names.iter().enumerate() {
            let offset = i * 4;
            if offset + 4 <= output.len() {
                let value = u32::from_le_bytes([
                    output[offset],
                    output[offset + 1],
                    output[offset + 2],
                    output[offset + 3],
                ]);
                state.registers.insert(name.to_string(), value as u64);
            }
        }

        // Parse flags (4 bytes at offset 32)
        if output.len() >= FLAGS_OFFSET_32 + FLAGS_SIZE_32 {
            state.flags = u32::from_le_bytes([
                output[FLAGS_OFFSET_32],
                output[FLAGS_OFFSET_32 + 1],
                output[FLAGS_OFFSET_32 + 2],
                output[FLAGS_OFFSET_32 + 3],
            ]) as u64;
        }

        // Parse memory locations (starting at offset 64)
        let mut offset = MEMORY_SECTION_OFFSET_32;
        let mut stack_slot = 0u64;
        // 32-bit: pairs of (value: u32, size: u32)
        while offset + 8 <= output.len() {
            let value = u32::from_le_bytes([
                output[offset],
                output[offset + 1],
                output[offset + 2],
                output[offset + 3],
            ]);
            let size = u32::from_le_bytes([
                output[offset + 4],
                output[offset + 5],
                output[offset + 6],
                output[offset + 7],
            ]);

            if value == 0 && size == 0 {
                break;
            }
            if size != 4 {
                break;
            }

            let pseudo_addr = 0xFFFF_FFFF_0000_0000 + stack_slot;
            state
                .memory_locations
                .insert(pseudo_addr, (value as u64).to_le_bytes().to_vec());
            stack_slot += 1;
            offset += 8;
        }

        Ok(state)
    }

    pub fn parse_from_output(output: &[u8]) -> Result<Self> {
        // Validate buffer size with proper bounds checking
        if output.len() < OUTPUT_BUFFER_SIZE {
            return Err(Error::Simulation(format!(
                "Output buffer too small: {} bytes, expected at least {} bytes",
                output.len(),
                OUTPUT_BUFFER_SIZE
            )));
        }

        let mut state = FinalState::new();

        // Parse registers (first 16 * 8 = 128 bytes)
        let register_names = [
            "rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp", "r8", "r9", "r10", "r11",
            "r12", "r13", "r14", "r15",
        ];

        for (i, &name) in register_names.iter().enumerate() {
            let offset = i * 8;
            if offset + 8 <= output.len() {
                let value = u64::from_le_bytes([
                    output[offset],
                    output[offset + 1],
                    output[offset + 2],
                    output[offset + 3],
                    output[offset + 4],
                    output[offset + 5],
                    output[offset + 6],
                    output[offset + 7],
                ]);
                state.registers.insert(name.to_string(), value);
            }
        }

        // Parse flags (at offset 128)
        if output.len() >= REGISTER_SECTION_SIZE + FLAGS_SECTION_SIZE {
            state.flags = u64::from_le_bytes([
                output[REGISTER_SECTION_SIZE],
                output[REGISTER_SECTION_SIZE + 1],
                output[REGISTER_SECTION_SIZE + 2],
                output[REGISTER_SECTION_SIZE + 3],
                output[REGISTER_SECTION_SIZE + 4],
                output[REGISTER_SECTION_SIZE + 5],
                output[REGISTER_SECTION_SIZE + 6],
                output[REGISTER_SECTION_SIZE + 7],
            ]);
        }

        // Parse memory locations (starting at offset 256)
        // The epilogue stores stack values as (value, size=8) pairs, not full memory regions.
        // We parse these as stack slot values for debugging purposes.
        // Format: [value: u64, size: u64] pairs ending with (0, 0) marker.
        let mut offset = MEMORY_SECTION_OFFSET;
        let mut stack_slot = 0u64;
        while offset + 16 <= output.len() {
            let value = u64::from_le_bytes([
                output[offset],
                output[offset + 1],
                output[offset + 2],
                output[offset + 3],
                output[offset + 4],
                output[offset + 5],
                output[offset + 6],
                output[offset + 7],
            ]);

            let size = u64::from_le_bytes([
                output[offset + 8],
                output[offset + 9],
                output[offset + 10],
                output[offset + 11],
                output[offset + 12],
                output[offset + 13],
                output[offset + 14],
                output[offset + 15],
            ]);

            if value == 0 && size == 0 {
                break; // End marker
            }

            // The epilogue stores stack values with size=8. If we see a different size,
            // stop parsing as the memory section may be corrupted or in an unexpected format.
            if size != 8 {
                break;
            }

            // Store stack values using pseudo-addresses (stack slot index)
            let pseudo_addr = 0xFFFF_FFFF_0000_0000 + stack_slot;
            state
                .memory_locations
                .insert(pseudo_addr, value.to_le_bytes().to_vec());
            stack_slot += 1;

            offset += 16;
        }

        Ok(state)
    }

    #[allow(dead_code)]
    pub fn get_register(&self, name: &str) -> Option<u64> {
        self.registers.get(name).copied()
    }

    #[allow(dead_code)]
    pub fn get_memory(&self, address: u64) -> Option<&Vec<u8>> {
        self.memory_locations.get(&address)
    }
}
