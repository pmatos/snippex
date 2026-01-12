use rusqlite::Connection;
use std::fs;
use std::path::PathBuf;
use std::process::Command;
use tempfile::TempDir;

fn create_test_binary() -> PathBuf {
    let test_dir = TempDir::new().unwrap();
    let source_path = test_dir.path().join("test.c");
    let binary_path = test_dir.path().join("test_binary");

    fs::write(
        &source_path,
        r#"
        #include <stdio.h>
        
        int add(int a, int b) {
            return a + b;
        }
        
        int multiply(int a, int b) {
            return a * b;
        }
        
        int main() {
            printf("Test binary\n");
            int result = add(5, 3);
            result = multiply(result, 2);
            return 0;
        }
    "#,
    )
    .unwrap();

    let output = Command::new("gcc")
        .args([
            "-o",
            binary_path.to_str().unwrap(),
            source_path.to_str().unwrap(),
        ])
        .output()
        .expect("Failed to compile test binary");

    if !output.status.success() {
        panic!(
            "Failed to compile test binary: {:?}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    let owned_path = binary_path.to_path_buf();
    std::mem::forget(test_dir);
    owned_path
}

#[test]
fn test_extract_command() {
    let test_binary = create_test_binary();
    let db_dir = TempDir::new().unwrap();
    let db_path = db_dir.path().join("test.db");

    let output = Command::new("cargo")
        .args([
            "run",
            "--",
            "extract",
            test_binary.to_str().unwrap(),
            "--database",
            db_path.to_str().unwrap(),
            "--verbose",
        ])
        .output()
        .expect("Failed to run snippex");

    assert!(
        output.status.success(),
        "Command failed: {:?}",
        String::from_utf8_lossy(&output.stderr)
    );

    let conn = Connection::open(&db_path).unwrap();

    let binary_count: i64 = conn
        .query_row("SELECT COUNT(*) FROM binaries", [], |row| row.get(0))
        .unwrap();
    assert_eq!(binary_count, 1, "Should have one binary entry");

    let extraction_count: i64 = conn
        .query_row("SELECT COUNT(*) FROM extractions", [], |row| row.get(0))
        .unwrap();
    assert_eq!(extraction_count, 1, "Should have one extraction entry");

    let (start_addr, end_addr, block_size): (i64, i64, usize) = conn
        .query_row(
            "SELECT start_address, end_address, LENGTH(assembly_block) FROM extractions",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .unwrap();

    assert!(
        start_addr < end_addr,
        "Start address should be less than end address"
    );
    assert_eq!(
        block_size,
        (end_addr - start_addr) as usize,
        "Block size should match address range"
    );
    assert!(block_size >= 16, "Block should be at least 16 bytes");
    assert!(block_size <= 1024, "Block should be at most 1024 bytes");

    fs::remove_file(&test_binary).ok();
}

#[test]
fn test_binary_info_storage() {
    let test_binary = create_test_binary();
    let db_dir = TempDir::new().unwrap();
    let db_path = db_dir.path().join("test.db");

    Command::new("cargo")
        .args([
            "run",
            "--",
            "extract",
            test_binary.to_str().unwrap(),
            "--database",
            db_path.to_str().unwrap(),
        ])
        .output()
        .expect("Failed to run snippex");

    let conn = Connection::open(&db_path).unwrap();

    let (path, size, hash, format, arch, endian): (String, i64, String, String, String, String) =
        conn.query_row(
            "SELECT path, size, hash, format, architecture, endianness FROM binaries",
            [],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                ))
            },
        )
        .unwrap();

    assert!(path.contains("test_binary"));
    assert!(size > 0, "Binary size should be positive");
    assert_eq!(hash.len(), 64, "SHA256 hash should be 64 characters");
    assert_eq!(format, "ELF");
    assert_eq!(arch, "x86_64");
    assert_eq!(endian, "little");

    fs::remove_file(&test_binary).ok();
}

#[test]
fn test_multiple_extractions_same_binary() {
    let test_binary = create_test_binary();
    let db_dir = TempDir::new().unwrap();
    let db_path = db_dir.path().join("test.db");

    for _ in 0..3 {
        Command::new("cargo")
            .args([
                "run",
                "--",
                "extract",
                test_binary.to_str().unwrap(),
                "--database",
                db_path.to_str().unwrap(),
            ])
            .output()
            .expect("Failed to run snippex");
    }

    let conn = Connection::open(&db_path).unwrap();

    let binary_count: i64 = conn
        .query_row("SELECT COUNT(*) FROM binaries", [], |row| row.get(0))
        .unwrap();
    assert_eq!(
        binary_count, 1,
        "Should have only one binary entry for same file"
    );

    let extraction_count: i64 = conn
        .query_row("SELECT COUNT(*) FROM extractions", [], |row| row.get(0))
        .unwrap();
    assert_eq!(extraction_count, 3, "Should have three extraction entries");

    fs::remove_file(&test_binary).ok();
}

#[test]
fn test_quiet_mode() {
    let test_binary = create_test_binary();
    let db_dir = TempDir::new().unwrap();
    let db_path = db_dir.path().join("test.db");

    let output = Command::new("cargo")
        .args([
            "run",
            "--",
            "extract",
            test_binary.to_str().unwrap(),
            "--database",
            db_path.to_str().unwrap(),
            "--quiet",
        ])
        .output()
        .expect("Failed to run snippex");

    assert!(output.status.success());
    assert!(
        output.stdout.is_empty(),
        "Should produce no output in quiet mode"
    );

    fs::remove_file(&test_binary).ok();
}
