#[cfg(test)]
mod tests {
    use crate::db::{BinaryInfo, Database};
    use tempfile::NamedTempFile;

    fn create_test_db() -> (Database, NamedTempFile) {
        let temp_file = NamedTempFile::new().unwrap();
        let mut db = Database::new(temp_file.path()).unwrap();
        db.init().unwrap();
        (db, temp_file)
    }

    #[test]
    fn test_database_initialization() {
        let (db, _temp) = create_test_db();

        let tables_count: i32 = db
            .conn
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type='table'",
                [],
                |row| row.get(0),
            )
            .unwrap();

        assert_eq!(
            tables_count, 4,
            "Should have 4 tables (binaries, extractions, analyses, and simulations)"
        );
    }

    #[test]
    fn test_store_extraction() {
        let (mut db, _temp) = create_test_db();

        let binary_info = BinaryInfo {
            path: "/test/binary".to_string(),
            size: 1024,
            hash: "abcdef123456".to_string(),
            format: "ELF".to_string(),
            architecture: "x86_64".to_string(),
            endianness: "little".to_string(),
            base_address: 0x400000,
        };

        let assembly_block = vec![0x90, 0x90, 0x90, 0x90];

        db.store_extraction(&binary_info, 0x1000, 0x1004, &assembly_block)
            .unwrap();

        let extraction_count: i32 = db
            .conn
            .query_row("SELECT COUNT(*) FROM extractions", [], |row| row.get(0))
            .unwrap();

        assert_eq!(extraction_count, 1);
    }

    #[test]
    fn test_duplicate_binary_handling() {
        let (mut db, _temp) = create_test_db();

        let binary_info = BinaryInfo {
            path: "/test/binary".to_string(),
            size: 1024,
            hash: "unique_hash_123".to_string(),
            format: "ELF".to_string(),
            architecture: "x86_64".to_string(),
            endianness: "little".to_string(),
            base_address: 0x400000,
        };

        let assembly_block = vec![0x90, 0x90];

        db.store_extraction(&binary_info, 0x1000, 0x1002, &assembly_block)
            .unwrap();
        db.store_extraction(&binary_info, 0x2000, 0x2002, &assembly_block)
            .unwrap();

        let binary_count: i32 = db
            .conn
            .query_row("SELECT COUNT(*) FROM binaries", [], |row| row.get(0))
            .unwrap();

        assert_eq!(binary_count, 1, "Should only have one binary entry");

        let extraction_count: i32 = db
            .conn
            .query_row("SELECT COUNT(*) FROM extractions", [], |row| row.get(0))
            .unwrap();

        assert_eq!(extraction_count, 2, "Should have two extraction entries");
    }
}
