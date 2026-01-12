#!/usr/bin/env python3
"""
Snippex Assembly Analyzer

A utility script that takes an assembly file, assembles it with NASM,
and analyzes it using snippex without leaving database traces.

Usage:
    python3 scripts/analyze-asm.py --32 example.asm
    python3 scripts/analyze-asm.py --64 example.asm
"""

import argparse
import os
import subprocess
import sys
import tempfile
from pathlib import Path


def check_dependencies():
    """Check if required tools are available."""
    required_tools = ['nasm', 'ld', 'objdump']
    missing = []
    
    for tool in required_tools:
        if subprocess.run(['which', tool], capture_output=True).returncode != 0:
            missing.append(tool)
    
    if missing:
        print(f"Error: Missing required tools: {', '.join(missing)}", file=sys.stderr)
        print("Please install them and try again.", file=sys.stderr)
        return False
    
    return True


def find_snippex():
    """Find the snippex binary."""
    # Try release build first, then debug build
    script_dir = Path(__file__).parent.parent
    candidates = [
        script_dir / "target" / "release" / "snippex",
        script_dir / "target" / "debug" / "snippex",
    ]
    
    for candidate in candidates:
        if candidate.exists() and candidate.is_file():
            return candidate
    
    # Try system PATH
    if subprocess.run(['which', 'snippex'], capture_output=True).returncode == 0:
        return 'snippex'
    
    print("Error: snippex binary not found.", file=sys.stderr)
    print("Please build snippex first: cargo build --release", file=sys.stderr)
    return None


def create_nasm_content(asm_file, bits):
    """Create NASM source with proper preamble."""
    with open(asm_file, 'r') as f:
        asm_content = f.read().strip()
    
    # Process the assembly content to handle inline semicolons
    lines = []
    for line in asm_content.split('\n'):
        line = line.strip()
        if line and not line.startswith(';'):
            # Split on semicolons but keep them as separate instructions
            if ';' in line:
                parts = line.split(';')
                for part in parts:
                    part = part.strip()
                    if part and not part.startswith(';'):
                        lines.append(f"    {part}")
            else:
                lines.append(f"    {line}")
    
    asm_instructions = '\n'.join(lines)
    
    # Create NASM file with preamble
    nasm_content = f"""BITS {bits}
section .text
global _start

_start:
{asm_instructions}
user_code_end:

; Exit syscall for completeness
"""
    
    if bits == 64:
        nasm_content += """    mov rax, 60     ; sys_exit
    mov rdi, 0      ; exit status
    syscall
"""
    else:
        nasm_content += """    mov eax, 1      ; sys_exit
    mov ebx, 0      ; exit status
    int 0x80
"""
    
    return nasm_content, asm_content


def assemble_and_link(nasm_content, bits, temp_dir):
    """Assemble the NASM content and link it into an ELF executable."""
    asm_file = temp_dir / "input.asm"
    obj_file = temp_dir / "input.o"
    elf_file = temp_dir / "input"
    
    # Write NASM source
    with open(asm_file, 'w') as f:
        f.write(nasm_content)
    
    # Assemble with NASM
    nasm_format = "elf64" if bits == 64 else "elf32"
    nasm_cmd = ["nasm", "-f", nasm_format, "-o", str(obj_file), str(asm_file)]
    
    result = subprocess.run(nasm_cmd, capture_output=True, text=True)
    if result.returncode != 0:
        print(f"NASM assembly failed:", file=sys.stderr)
        print(result.stderr, file=sys.stderr)
        return None
    
    # Link to create executable
    ld_cmd = ["ld", "-o", str(elf_file), str(obj_file)]
    if bits == 32:
        ld_cmd.insert(1, "-m")
        ld_cmd.insert(2, "elf_i386")
    result = subprocess.run(ld_cmd, capture_output=True, text=True)
    if result.returncode != 0:
        print(f"Linking failed:", file=sys.stderr)
        print(result.stderr, file=sys.stderr)
        return None
    
    return elf_file


def find_user_code_range(elf_file, bits):
    """Find the address range of user code by parsing the ELF with objdump."""
    # Use objdump to disassemble and find our labels
    objdump_cmd = ["objdump", "-d", str(elf_file)]
    result = subprocess.run(objdump_cmd, capture_output=True, text=True)
    
    if result.returncode != 0:
        print(f"objdump failed:", file=sys.stderr)
        print(result.stderr, file=sys.stderr)
        return None
    
    
    start_addr = None
    end_addr = None
    
    lines = result.stdout.split('\n')
    for i, line in enumerate(lines):
        # Look for _start symbol
        if '<_start>' in line:
            # Extract address from the line like "0000000000401000 <_start>:"
            addr_str = line.split()[0]
            start_addr = int(addr_str, 16)
        
        # Look for user_code_end label
        if '<user_code_end>' in line:
            # Extract address from the line like "000000000040100c <user_code_end>:"
            addr_str = line.split()[0]
            end_addr = int(addr_str, 16)
            break
    
    if start_addr is None:
        print("Could not find _start symbol", file=sys.stderr)
        return None
    
    if end_addr is None:
        print("Could not find end of user code", file=sys.stderr)
        return None
    
    return start_addr, end_addr


def extract_with_snippex(snippex_path, elf_file, db_file, start_addr, end_addr):
    """Extract the assembly block using snippex with specific range."""
    extract_cmd = [
        str(snippex_path), "extract", 
        "--database", str(db_file),
        "--range", f"0x{start_addr:x}", f"0x{end_addr:x}",
        str(elf_file)
    ]
    
    result = subprocess.run(extract_cmd, capture_output=True, text=True)
    if result.returncode != 0:
        print(f"Snippex extraction failed:", file=sys.stderr)
        print(result.stderr, file=sys.stderr)
        return False
    
    return True


def analyze_with_snippex(snippex_path, db_file):
    """Analyze the extracted block using snippex."""
    # First check if there are any blocks
    list_cmd = [str(snippex_path), "list", "--database", str(db_file)]
    result = subprocess.run(list_cmd, capture_output=True, text=True)
    if result.returncode != 0 or not result.stdout.strip():
        print("No blocks found to analyze", file=sys.stderr)
        return False
    
    # Analyze block #1
    analyze_cmd = [
        str(snippex_path), "analyze", "1",
        "--database", str(db_file),
        "--verbose"
    ]
    
    result = subprocess.run(analyze_cmd, capture_output=True, text=True)
    if result.returncode != 0:
        print(f"Snippex analysis failed:", file=sys.stderr)
        print(result.stderr, file=sys.stderr)
        return False
    
    # Print the analysis output
    print(result.stdout)
    return True


def main():
    parser = argparse.ArgumentParser(
        description="Assemble and analyze assembly code with snippex",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 scripts/analyze-asm.py --64 example.asm
  python3 scripts/analyze-asm.py --32 simple_mov.asm
        """
    )
    
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--32', action='store_true', help='Assemble for 32-bit x86')
    group.add_argument('--64', action='store_true', help='Assemble for 64-bit x86_64')
    
    parser.add_argument('asm_file', help='Assembly file to analyze')
    parser.add_argument('--verbose', '-v', action='store_true', help='Show verbose output')
    
    args = parser.parse_args()
    
    # Determine architecture
    bits = 64 if getattr(args, '64') else 32
    
    # Validate input file
    asm_file = Path(args.asm_file)
    if not asm_file.exists():
        print(f"Error: Assembly file '{asm_file}' not found", file=sys.stderr)
        return 1
    
    # Check dependencies
    if not check_dependencies():
        return 1
    
    # Find snippex binary
    snippex_path = find_snippex()
    if not snippex_path:
        return 1
    
    if args.verbose:
        print(f"Using snippex: {snippex_path}")
        print(f"Assembling {asm_file} for {bits}-bit architecture")
    
    # Create temporary directory for all operations
    with tempfile.TemporaryDirectory(prefix="snippex_analyze_") as temp_dir:
        temp_path = Path(temp_dir)
        
        try:
            # Read and prepare assembly content
            if args.verbose:
                print("Creating NASM source with preamble...")
            nasm_content, original_asm = create_nasm_content(asm_file, bits)
            
            # Assemble and link
            if args.verbose:
                print("Assembling and linking...")
            elf_file = assemble_and_link(nasm_content, bits, temp_path)
            if not elf_file:
                return 1
            
            # Find the address range of user code only
            if args.verbose:
                print("Finding user code address range...")
            addr_range = find_user_code_range(elf_file, bits)
            if not addr_range:
                return 1
            
            start_addr, end_addr = addr_range
            if args.verbose:
                print(f"User code range: 0x{start_addr:x} - 0x{end_addr:x}")
            
            # Create temporary database
            db_file = temp_path / "temp.db"
            
            # Extract with snippex using specific range
            if args.verbose:
                print("Extracting user code block...")
            if not extract_with_snippex(snippex_path, elf_file, db_file, start_addr, end_addr):
                return 1
            
            # Analyze with snippex
            if args.verbose:
                print("Analyzing block...")
                print("=" * 60)
            
            if not analyze_with_snippex(snippex_path, db_file):
                return 1
            
        except Exception as e:
            print(f"Error: {e}", file=sys.stderr)
            return 1
    
    # Temporary directory and all files are automatically cleaned up
    return 0


if __name__ == "__main__":
    sys.exit(main())