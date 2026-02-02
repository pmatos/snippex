use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};

use super::sandbox::SANDBOX_BASE;
use super::state::InitialState;
use super::TargetArch;
use crate::analyzer::{BlockAnalysis, MemoryAccess, PointerRegisterUsage};

/// Base address for dynamically allocated pointer buffers within the sandbox.
/// This is offset from SANDBOX_BASE to avoid conflicts with binary sections.
const POINTER_BUFFER_BASE: u64 = SANDBOX_BASE + 0x0800_0000; // 128MB into sandbox

/// Maximum size for a single pointer buffer (1MB).
const MAX_BUFFER_SIZE: usize = 0x10_0000;

/// Alignment for pointer buffers (page-aligned).
const BUFFER_ALIGNMENT: u64 = 0x1000;

pub struct RandomStateGenerator {
    rng: StdRng,
    /// Next available address for buffer allocation
    next_buffer_addr: u64,
    target_arch: TargetArch,
}

impl Default for RandomStateGenerator {
    fn default() -> Self {
        Self::new()
    }
}

impl RandomStateGenerator {
    pub fn new() -> Self {
        Self {
            rng: StdRng::from_rng(&mut rand::rng()),
            next_buffer_addr: POINTER_BUFFER_BASE,
            target_arch: TargetArch::X86_64,
        }
    }

    pub fn for_target(arch: TargetArch) -> Self {
        Self {
            rng: StdRng::from_rng(&mut rand::rng()),
            next_buffer_addr: POINTER_BUFFER_BASE,
            target_arch: arch,
        }
    }

    pub fn with_seed(seed: u64) -> Self {
        Self {
            rng: StdRng::seed_from_u64(seed),
            next_buffer_addr: POINTER_BUFFER_BASE,
            target_arch: TargetArch::X86_64,
        }
    }

    /// Resets the buffer allocator for a new simulation run.
    pub fn reset_buffer_allocator(&mut self) {
        self.next_buffer_addr = POINTER_BUFFER_BASE;
    }

    /// Allocates a buffer for a pointer register and returns the address the register should hold.
    ///
    /// The buffer is sized to accommodate all memory accesses from `min_offset` to `max_offset + max_access_size`.
    /// The returned address is adjusted so that `register + min_offset` points to the start of the buffer.
    fn allocate_pointer_buffer(&mut self, usage: &PointerRegisterUsage) -> Option<(u64, usize)> {
        // Calculate required buffer size
        let offset_range = (usage.max_offset - usage.min_offset) as usize;
        let buffer_size = offset_range + usage.max_access_size;

        // Clamp to maximum buffer size
        let buffer_size = buffer_size.min(MAX_BUFFER_SIZE);

        // Align to page boundary
        let aligned_size = (buffer_size as u64).div_ceil(BUFFER_ALIGNMENT) * BUFFER_ALIGNMENT;

        // Allocate from the buffer region
        let buffer_start = self.next_buffer_addr;
        self.next_buffer_addr += aligned_size;

        // Calculate the register value: it should point such that [reg + min_offset] = buffer_start
        // So: reg = buffer_start - min_offset
        let register_value = if usage.min_offset >= 0 {
            buffer_start.saturating_sub(usage.min_offset as u64)
        } else {
            buffer_start.saturating_add((-usage.min_offset) as u64)
        };

        Some((register_value, buffer_size))
    }

    pub fn generate_initial_state(&mut self, analysis: &BlockAnalysis) -> InitialState {
        let mut state = InitialState::new();

        // Reset buffer allocator for this simulation
        self.reset_buffer_allocator();

        // First, handle pointer registers - these get valid buffer addresses
        for (register, usage) in &analysis.pointer_registers {
            if let Some((reg_value, buffer_size)) = self.allocate_pointer_buffer(usage) {
                state.set_register(register, reg_value);

                // Initialize the buffer with random data
                let buffer_data = self.generate_memory_data(buffer_size);

                // Calculate actual buffer start address (reg_value + min_offset)
                let buffer_addr = if usage.min_offset >= 0 {
                    reg_value.saturating_add(usage.min_offset as u64)
                } else {
                    reg_value.saturating_sub((-usage.min_offset) as u64)
                };

                state.set_memory(buffer_addr, buffer_data);
            }
        }

        // Generate random values for live-in registers that aren't pointer registers
        for register in &analysis.live_in_registers {
            // Skip registers already set as pointers
            if analysis.pointer_registers.contains_key(register) {
                continue;
            }

            let value = self.generate_register_value(register);
            state.set_register(register, value);
        }

        // Set up stack with random but realistic values
        self.setup_stack_frame(&mut state);

        // Generate memory values for accessed locations (for non-register-based accesses)
        for memory_access in &analysis.memory_accesses {
            if let Some(addr) = self.estimate_memory_address(memory_access) {
                // Don't overwrite pointer buffer memory
                if !state.memory_locations.contains_key(&addr) {
                    let data = self.generate_memory_data(memory_access.size);
                    state.set_memory(addr, data);
                }
            }
        }

        state
    }

    fn generate_register_value(&mut self, register: &str) -> u64 {
        if self.target_arch.is_32bit() {
            return self.generate_register_value_32(register);
        }
        match register {
            "rsp" | "esp" => {
                let base = 0x7ffd00000000u64;
                let offset = self.rng.random_range(0x1000..0x10000);
                base + offset
            }
            "rbp" | "ebp" => {
                let base = 0x7ffd00000000u64;
                let offset = self.rng.random_range(0x1000..0x10000);
                base + offset
            }
            _ => {
                let mut value = self.rng.random::<u64>();
                if value < 0x1000 {
                    value += 0x1000;
                }
                if value >= 0xffff800000000000 {
                    value &= 0x7fffffffffffffff;
                }
                value
            }
        }
    }

    fn generate_register_value_32(&mut self, register: &str) -> u64 {
        match register {
            "rsp" | "esp" => {
                let base = 0x7ffd0000u64;
                let offset = self.rng.random_range(0x1000u64..0x10000u64);
                base + offset
            }
            "rbp" | "ebp" => {
                let base = 0x7ffd0000u64;
                let offset = self.rng.random_range(0x1000u64..0x10000u64);
                base + offset
            }
            _ => {
                let mut value = self.rng.random::<u32>() as u64;
                if value < 0x1000 {
                    value += 0x1000;
                }
                // Avoid kernel space (above 0xC0000000) on 32-bit Linux
                if value >= 0xC0000000 {
                    value &= 0x7FFFFFFF;
                }
                value
            }
        }
    }

    fn setup_stack_frame(&mut self, state: &mut InitialState) {
        // Generate some random stack values
        let stack_depth = self.rng.random_range(1..8);
        for _ in 0..stack_depth {
            let value = self.rng.random::<u64>();
            state.add_stack_value(value);
        }
    }

    fn estimate_memory_address(&mut self, memory_access: &MemoryAccess) -> Option<u64> {
        if self.target_arch.is_32bit() {
            if memory_access.is_stack {
                let base = 0x7ffd0000u64;
                let offset = self.rng.random_range(0x1000..0x10000);
                Some(base + offset)
            } else {
                let base = 0x08048000u64;
                let offset = self.rng.random_range(0x1000..0x100000);
                Some(base + offset)
            }
        } else if memory_access.is_stack {
            let base = 0x7ffd00000000u64;
            let offset = self.rng.random_range(0x1000..0x10000);
            Some(base + offset)
        } else {
            let base = 0x555555554000u64;
            let offset = self.rng.random_range(0x1000..0x100000);
            Some(base + offset)
        }
    }

    fn generate_memory_data(&mut self, size: usize) -> Vec<u8> {
        let mut data = vec![0u8; size];
        self.rng.fill(&mut data[..]);

        // Avoid generating problematic patterns
        for byte in &mut data {
            // Avoid NULL bytes in strings
            if *byte == 0 {
                *byte = 0x20; // space character
            }
        }

        data
    }

    #[allow(dead_code)]
    pub fn random_u64(&mut self) -> u64 {
        self.rng.random()
    }

    #[allow(dead_code)]
    pub fn random_bytes(&mut self, size: usize) -> Vec<u8> {
        let mut data = vec![0u8; size];
        self.rng.fill(&mut data[..]);
        data
    }
}
