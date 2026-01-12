#!/usr/bin/env python3
"""
Assembly Test Annotator for Snippex

Automatically analyzes assembly test files and adds LIVEIN, LIVEOUT, EXITS,
and MEMORY annotations using Snippex's analyzer.
"""

import argparse
import json
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Dict, List, Optional, Set


class TestAnnotator:
    def __init__(self, snippex_path: Path, verbose: bool = False, dry_run: bool = False):
        self.snippex_path = snippex_path
        self.verbose = verbose
        self.dry_run = dry_run
        self.stats = {"annotated": 0, "skipped": 0, "errors": 0}

    def has_annotations(self, content: str) -> bool:
        """Check if file already has LIVEIN/LIVEOUT annotations."""
        return "; LIVEIN:" in content or "; LIVEOUT:" in content

    def detect_bits(self, content: str) -> int:
        """Detect architecture bits from file content."""
        # Check for BITS comment
        match = re.search(r"; BITS:\s*(\d+)", content)
        if match:
            return int(match.group(1))

        # Check assembly content for 64-bit registers
        if re.search(r"\b(rax|rbx|rcx|rdx|rsi|rdi|rbp|rsp|r\d+)\b", content, re.IGNORECASE):
            return 64

        return 64  # Default to 64-bit

    def analyze_assembly(self, asm_file: Path, bits: int) -> Optional[Dict]:
        """Analyze assembly file using Snippex and return analysis results."""
        with tempfile.TemporaryDirectory() as tmpdir:
            tmpdir_path = Path(tmpdir)
            db_path = tmpdir_path / "temp.db"

            # Compile assembly to binary
            asm_content = asm_file.read_text()

            # Add proper NASM preamble
            bits_directive = f"BITS {bits}"
            if "BITS" not in asm_content:
                asm_content = f"{bits_directive}\n{asm_content}"

            if "section" not in asm_content.lower():
                asm_content = f"{bits_directive}\nsection .text\n{asm_content}"

            if "global _start" not in asm_content and "_start:" not in asm_content:
                asm_content = f"{bits_directive}\nsection .text\nglobal _start\n_start:\n{asm_content}"

            # Write temporary assembly file
            temp_asm = tmpdir_path / "input.asm"
            temp_asm.write_text(asm_content)

            try:
                # Assemble
                obj_file = tmpdir_path / "input.o"
                result = subprocess.run(
                    ["nasm", f"-f", "elf64" if bits == 64 else "elf32", "-o", str(obj_file), str(temp_asm)],
                    capture_output=True,
                    text=True,
                )
                if result.returncode != 0:
                    print(f"Error assembling {asm_file.name}: {result.stderr}")
                    return None

                # Link
                bin_file = tmpdir_path / "input"
                arch_flag = "elf_x86_64" if bits == 64 else "elf_i386"
                result = subprocess.run(
                    ["ld", "-m", arch_flag, "-o", str(bin_file), str(obj_file)],
                    capture_output=True,
                    text=True,
                )
                if result.returncode != 0:
                    print(f"Error linking {asm_file.name}: {result.stderr}")
                    return None

                # Extract with Snippex
                result = subprocess.run(
                    [
                        str(self.snippex_path),
                        "extract",
                        "--database", str(db_path),
                        str(bin_file),
                    ],
                    capture_output=True,
                    text=True,
                )
                if result.returncode != 0:
                    print(f"Error extracting {asm_file.name}: {result.stderr}")
                    return None

                # Analyze with Snippex
                result = subprocess.run(
                    [
                        str(self.snippex_path),
                        "analyze",
                        "--database", str(db_path),
                        "1",  # Analyze first block
                    ],
                    capture_output=True,
                    text=True,
                )
                if result.returncode != 0:
                    print(f"Error analyzing {asm_file.name}: {result.stderr}")
                    return None

                # Parse analysis output
                return self.parse_analysis_output(result.stdout)

            except Exception as e:
                print(f"Exception analyzing {asm_file.name}: {e}")
                return None

    def parse_analysis_output(self, output: str) -> Dict:
        """Parse Snippex analysis output."""
        result = {
            "live_in": set(),
            "live_out": set(),
            "exits": [],
            "memory": [],
        }

        # Parse live-in registers
        livein_match = re.search(r"Live-in Registers.*?:\s*(.*?)(?:\n\n|\nLive-out)", output, re.DOTALL)
        if livein_match:
            content = livein_match.group(1)
            for line in content.split("\n"):
                line = line.strip()
                if line.startswith("- "):
                    reg = line[2:].strip()
                    result["live_in"].add(reg)

        # Parse live-out registers
        liveout_match = re.search(r"Live-out Registers.*?:\s*(.*?)(?:\n\n|\nExit)", output, re.DOTALL)
        if liveout_match:
            content = liveout_match.group(1)
            for line in content.split("\n"):
                line = line.strip()
                if line.startswith("- "):
                    reg = line[2:].strip()
                    result["live_out"].add(reg)

        # Parse exit points
        exits_match = re.search(r"Exit Points.*?:\s*(.*?)(?:\n\n|\nMemory)", output, re.DOTALL)
        if exits_match:
            content = exits_match.group(1)
            for line in content.split("\n"):
                line = line.strip()
                if line.startswith("- "):
                    result["exits"].append(line[2:].strip())

        # Parse memory accesses
        memory_match = re.search(r"Memory Accesses.*?:\s*(.*?)$", output, re.DOTALL)
        if memory_match:
            content = memory_match.group(1)
            for line in content.split("\n"):
                line = line.strip()
                if line.startswith("- "):
                    result["memory"].append(line[2:].strip())

        return result

    def annotate_file(self, asm_file: Path) -> bool:
        """Annotate a single assembly file."""
        try:
            content = asm_file.read_text()

            # Skip if already annotated
            if self.has_annotations(content):
                if self.verbose:
                    print(f"Skipping {asm_file.name} (already annotated)")
                self.stats["skipped"] += 1
                return True

            # Detect architecture
            bits = self.detect_bits(content)

            if self.verbose:
                print(f"Analyzing {asm_file.name} ({bits}-bit)...")

            # Analyze assembly
            analysis = self.analyze_assembly(asm_file, bits)
            if not analysis:
                self.stats["errors"] += 1
                return False

            # Build annotation lines
            annotations = []

            # Add LIVEIN
            if analysis["live_in"]:
                livein_str = ", ".join(sorted(analysis["live_in"]))
                annotations.append(f"; LIVEIN: {livein_str}")
            else:
                annotations.append("; LIVEIN:")

            # Add LIVEOUT
            if analysis["live_out"]:
                liveout_str = ", ".join(sorted(analysis["live_out"]))
                annotations.append(f"; LIVEOUT: {liveout_str}")
            else:
                annotations.append("; LIVEOUT:")

            # Add EXITS
            if analysis["exits"]:
                exits_str = ", ".join(analysis["exits"])
                annotations.append(f"; EXITS: {exits_str}")
            else:
                annotations.append("; EXITS:")

            # Add MEMORY
            if analysis["memory"]:
                memory_str = ", ".join(analysis["memory"])
                annotations.append(f"; MEMORY: {memory_str}")
            else:
                annotations.append("; MEMORY:")

            # Insert annotations after BITS line (if present) or at the start
            lines = content.split("\n")
            insert_pos = 0

            for i, line in enumerate(lines):
                if line.startswith("; BITS:") or line.startswith("; SOURCE:") or line.startswith("; FEX_SHA256:"):
                    insert_pos = i + 1
                elif line.strip() and not line.startswith(";"):
                    break

            # Insert annotations
            new_lines = lines[:insert_pos] + annotations + lines[insert_pos:]
            new_content = "\n".join(new_lines)

            if self.dry_run:
                print(f"Would annotate {asm_file.name}:")
                for ann in annotations:
                    print(f"  {ann}")
            else:
                asm_file.write_text(new_content)
                print(f"Annotated: {asm_file.name}")

            self.stats["annotated"] += 1
            return True

        except Exception as e:
            print(f"Error annotating {asm_file.name}: {e}")
            self.stats["errors"] += 1
            return False

    def annotate_directory(self, test_dir: Path, pattern: str = "*.asm") -> None:
        """Annotate all assembly files in a directory."""
        test_files = sorted(test_dir.glob(pattern))

        if not test_files:
            print(f"No files matching {pattern} found in {test_dir}")
            return

        print(f"Found {len(test_files)} test files")
        if self.dry_run:
            print("DRY RUN MODE - no files will be modified")

        for test_file in test_files:
            self.annotate_file(test_file)

        print("\n=== Annotation Summary ===")
        print(f"Total files processed: {len(test_files)}")
        print(f"Successfully annotated: {self.stats['annotated']}")
        print(f"Skipped (already annotated): {self.stats['skipped']}")
        print(f"Errors: {self.stats['errors']}")


def main():
    parser = argparse.ArgumentParser(
        description="Automatically annotate assembly test files with LIVEIN/LIVEOUT/EXITS/MEMORY"
    )
    parser.add_argument(
        "test_dir",
        type=Path,
        nargs="?",
        default=Path("tests/asm"),
        help="Directory containing test files (default: tests/asm)",
    )
    parser.add_argument(
        "--pattern",
        type=str,
        default="fex_*.asm",
        help="File pattern to match (default: fex_*.asm)",
    )
    parser.add_argument(
        "--snippex",
        type=Path,
        default=Path("target/release/snippex"),
        help="Path to snippex binary (default: target/release/snippex)",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Show what would be annotated without modifying files",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Enable verbose output",
    )

    args = parser.parse_args()

    # Check if snippex binary exists
    if not args.snippex.exists():
        print(f"Error: Snippex binary not found at {args.snippex}")
        print("Build it first with: cargo build --release")
        sys.exit(1)

    # Check if test directory exists
    if not args.test_dir.exists():
        print(f"Error: Test directory not found: {args.test_dir}")
        sys.exit(1)

    annotator = TestAnnotator(
        snippex_path=args.snippex,
        verbose=args.verbose,
        dry_run=args.dry_run,
    )

    annotator.annotate_directory(args.test_dir, args.pattern)


if __name__ == "__main__":
    main()