#!/usr/bin/env python3
"""
FEX Test Extractor for Snippex

Extracts NASM assembly tests from FEX-Emu repository, removes JSON headers,
and converts them to Snippex's test format. Tracks extracted tests by SHA256
to avoid duplicates across runs.
"""

import argparse
import hashlib
import json
import os
import re
import sys
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple


class FEXTestExtractor:
    def __init__(
        self,
        fex_path: Path,
        output_dir: Path,
        mapping_file: Path,
        dry_run: bool = False,
        force: bool = False,
        category: Optional[str] = None,
    ):
        self.fex_path = fex_path
        self.output_dir = output_dir
        self.mapping_file = mapping_file
        self.dry_run = dry_run
        self.force = force
        self.category = category
        self.mapping: Dict = {}
        self.stats = {"extracted": 0, "skipped": 0, "errors": 0}

    def load_mapping(self) -> None:
        """Load the extraction mapping file if it exists."""
        if self.mapping_file.exists():
            try:
                with open(self.mapping_file, "r") as f:
                    self.mapping = json.load(f)
            except json.JSONDecodeError as e:
                print(f"Warning: Could not parse mapping file: {e}")
                self.mapping = {}
        else:
            self.mapping = {}

    def save_mapping(self) -> None:
        """Save the extraction mapping file."""
        if not self.dry_run:
            with open(self.mapping_file, "w") as f:
                json.dump(self.mapping, f, indent=2)

    def calculate_sha256(self, content: str) -> str:
        """Calculate SHA256 hash of content."""
        return hashlib.sha256(content.encode("utf-8")).hexdigest()

    def find_asm_files(self) -> List[Path]:
        """Find all .asm files in the FEX unittests/ASM directory."""
        asm_dir = self.fex_path / "unittests" / "ASM"
        if not asm_dir.exists():
            print(f"Error: FEX ASM directory not found: {asm_dir}")
            sys.exit(1)

        asm_files = []
        for root, dirs, files in os.walk(asm_dir):
            root_path = Path(root)
            rel_path = root_path.relative_to(asm_dir)

            # Filter by category if specified
            if self.category:
                if rel_path == Path(".") and self.category != ".":
                    # Skip root files if category specified
                    continue
                elif not (
                    str(rel_path).startswith(self.category)
                    or str(rel_path) == self.category
                ):
                    continue

            for file in files:
                if file.endswith(".asm"):
                    asm_files.append(root_path / file)

        return sorted(asm_files)

    def extract_json_header(self, content: str) -> Tuple[Optional[Dict], str]:
        """
        Extract JSON header from FEX test if present.
        Returns (json_data, remaining_content).
        """
        # Match %ifdef CONFIG ... %endif block
        pattern = r"%ifdef\s+CONFIG\s*\n(.*?)\n%endif"
        match = re.search(pattern, content, re.DOTALL)

        if not match:
            return None, content

        json_str = match.group(1).strip()
        try:
            json_data = json.loads(json_str)
            # Remove the JSON header from content
            remaining = content[: match.start()] + content[match.end() :]
            return json_data, remaining.strip()
        except json.JSONDecodeError:
            # Not valid JSON, return as-is
            return None, content

    def detect_bits(self, json_data: Optional[Dict], asm_content: str) -> str:
        """Detect whether test is 32-bit or 64-bit."""
        # Check JSON RegData for 64-bit registers
        if json_data and "RegData" in json_data:
            reg_data = json_data["RegData"]
            # Check for 64-bit register names
            for reg in reg_data.keys():
                if reg.upper() in ["RAX", "RBX", "RCX", "RDX", "RSI", "RDI",
                                   "RBP", "RSP", "R8", "R9", "R10", "R11",
                                   "R12", "R13", "R14", "R15"]:
                    return "64"

        # Check assembly content for 64-bit registers
        asm_lower = asm_content.lower()
        if any(reg in asm_lower for reg in ["rax", "rbx", "rcx", "rdx", "rsi",
                                              "rdi", "rbp", "rsp", "r8", "r9",
                                              "r10", "r11", "r12", "r13", "r14", "r15"]):
            return "64"

        # Default to 64-bit (most FEX tests are x86_64)
        return "64"

    def generate_output_filename(self, fex_path: Path, asm_dir: Path) -> str:
        """Generate output filename based on FEX test path."""
        rel_path = fex_path.relative_to(asm_dir)

        # Convert path to filename: TwoByte/0F_10.asm -> fex_twobyte_0f_10.asm
        parts = list(rel_path.parts[:-1]) + [rel_path.stem]
        filename = "_".join(parts).lower()
        filename = re.sub(r"[^a-z0-9_]", "_", filename)
        filename = re.sub(r"_+", "_", filename)  # Remove multiple underscores

        return f"fex_{filename}.asm"

    def extract_test(self, fex_file: Path) -> bool:
        """
        Extract a single FEX test file.
        Returns True if successful, False otherwise.
        """
        try:
            # Read original file
            with open(fex_file, "r", encoding="utf-8") as f:
                original_content = f.read()

            # Calculate SHA256 of original
            file_sha = self.calculate_sha256(original_content)

            # Check if already extracted
            if not self.force and file_sha in self.mapping:
                self.stats["skipped"] += 1
                return True

            # Extract JSON header and remaining ASM
            json_data, asm_content = self.extract_json_header(original_content)

            # Detect architecture
            bits = self.detect_bits(json_data, asm_content)

            # Generate output filename
            asm_dir = self.fex_path / "unittests" / "ASM"
            rel_path = fex_file.relative_to(asm_dir)
            output_filename = self.generate_output_filename(fex_file, asm_dir)
            output_path = self.output_dir / output_filename

            # Generate Snippex-style header
            header = f"; BITS: {bits}\n"
            header += f"; SOURCE: FEX {rel_path}\n"
            header += f"; FEX_SHA256: {file_sha}\n"

            # Combine header and ASM content
            final_content = header + asm_content

            if self.dry_run:
                print(f"Would extract: {rel_path} -> {output_filename}")
            else:
                # Ensure output directory exists
                self.output_dir.mkdir(parents=True, exist_ok=True)

                # Write output file
                with open(output_path, "w", encoding="utf-8") as f:
                    f.write(final_content)

                # Update mapping
                self.mapping[file_sha] = {
                    "source_path": str(rel_path),
                    "output_file": str(output_path),
                    "extracted_at": datetime.now().isoformat(),
                }

                print(f"Extracted: {rel_path} -> {output_filename}")

            self.stats["extracted"] += 1
            return True

        except Exception as e:
            print(f"Error extracting {fex_file}: {e}")
            self.stats["errors"] += 1
            return False

    def run(self) -> None:
        """Main extraction process."""
        print(f"Loading FEX tests from: {self.fex_path}")

        # Load existing mapping
        self.load_mapping()

        # Find all ASM files
        asm_files = self.find_asm_files()
        total = len(asm_files)

        if total == 0:
            print("No .asm files found!")
            return

        print(f"Found {total} test files")
        if self.category:
            print(f"Filtering by category: {self.category}")
        if self.dry_run:
            print("DRY RUN MODE - no files will be modified")

        # Extract each test
        for asm_file in asm_files:
            self.extract_test(asm_file)

        # Save mapping
        if not self.dry_run:
            self.save_mapping()

        # Print statistics
        print("\n=== Extraction Summary ===")
        print(f"Total files processed: {total}")
        print(f"Successfully extracted: {self.stats['extracted']}")
        print(f"Skipped (already extracted): {self.stats['skipped']}")
        print(f"Errors: {self.stats['errors']}")


def main():
    parser = argparse.ArgumentParser(
        description="Extract FEX tests into Snippex format"
    )
    parser.add_argument(
        "--fex-path",
        type=Path,
        default=Path("external/FEX"),
        help="Path to FEX submodule (default: external/FEX)",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path("tests/asm"),
        help="Output directory for extracted tests (default: tests/asm)",
    )
    parser.add_argument(
        "--mapping-file",
        type=Path,
        default=Path("tests/asm/.fex_extracted.json"),
        help="Path to extraction mapping file (default: tests/asm/.fex_extracted.json)",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Show what would be extracted without writing files",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="Re-extract even if already in mapping",
    )
    parser.add_argument(
        "--category",
        type=str,
        help="Only extract from specific FEX subdirectory (e.g., 'TwoByte', 'Primary')",
    )

    args = parser.parse_args()

    # Validate FEX path
    if not args.fex_path.exists():
        print(f"Error: FEX path does not exist: {args.fex_path}")
        print("Have you initialized the git submodule?")
        print("  git submodule update --init --recursive")
        sys.exit(1)

    # Create extractor and run
    extractor = FEXTestExtractor(
        fex_path=args.fex_path,
        output_dir=args.output_dir,
        mapping_file=args.mapping_file,
        dry_run=args.dry_run,
        force=args.force,
        category=args.category,
    )

    extractor.run()


if __name__ == "__main__":
    main()