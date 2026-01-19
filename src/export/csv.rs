//! CSV export functionality for validation results and block data.

use anyhow::Result;
use serde::Serialize;
use std::io::Write;
use std::path::Path;

/// Configuration for CSV export.
#[derive(Debug, Clone, Default)]
pub struct CsvExportConfig {
    /// Include register diff details in output
    #[allow(dead_code)]
    pub include_register_diff: bool,
    /// Include memory diff details in output
    #[allow(dead_code)]
    pub include_memory_diff: bool,
    /// Include flag breakdown in output
    #[allow(dead_code)]
    pub include_flag_breakdown: bool,
    /// Append to existing file instead of overwriting
    pub append: bool,
}

/// A row in the validation results CSV export.
#[derive(Debug, Clone, Serialize)]
pub struct ValidationResultRow {
    pub timestamp: String,
    pub block_id: usize,
    pub binary_path: String,
    pub start_address: String,
    pub end_address: String,
    pub block_size: usize,
    pub native_exit_code: String,
    pub fex_exit_code: String,
    pub status: String,
    pub passed: String,
    pub execution_time_ms: f64,
    pub error_message: String,
    pub native_flags: String,
    pub fex_flags: String,
    pub flags_match: String,
    pub register_diff_count: usize,
    pub memory_diff_count: usize,
}

/// A row for block metadata CSV export.
#[allow(dead_code)]
#[derive(Debug, Clone, Serialize)]
pub struct BlockMetadataRow {
    pub block_id: i64,
    pub binary_path: String,
    pub binary_hash: String,
    pub start_address: String,
    pub end_address: String,
    pub block_size: usize,
    pub created_at: String,
    pub analysis_status: String,
    pub instruction_count: Option<u32>,
    pub live_in_registers: String,
    pub live_out_registers: String,
    pub simulation_count: usize,
}

/// A row for simulation results CSV export.
#[allow(dead_code)]
#[derive(Debug, Clone, Serialize)]
pub struct SimulationResultRow {
    pub block_id: i64,
    pub simulation_id: String,
    pub emulator: String,
    pub exit_code: i32,
    pub execution_time_ms: f64,
    pub final_flags: String,
    pub register_count: usize,
    pub memory_location_count: usize,
    pub created_at: String,
}

/// CSV Exporter for writing validation and block data.
pub struct CsvExporter {
    config: CsvExportConfig,
}

impl CsvExporter {
    pub fn new(config: CsvExportConfig) -> Self {
        Self { config }
    }

    #[allow(dead_code)]
    pub fn with_defaults() -> Self {
        Self::new(CsvExportConfig::default())
    }

    /// Export validation results to a CSV file.
    pub fn export_validation_results<P: AsRef<Path>>(
        &self,
        path: P,
        rows: &[ValidationResultRow],
    ) -> Result<()> {
        let file = if self.config.append && path.as_ref().exists() {
            std::fs::OpenOptions::new()
                .append(true)
                .open(path.as_ref())?
        } else {
            std::fs::File::create(path.as_ref())?
        };

        let mut writer = csv::WriterBuilder::new()
            .has_headers(!self.config.append || !path.as_ref().exists())
            .from_writer(file);

        for row in rows {
            writer.serialize(row)?;
        }

        writer.flush()?;
        Ok(())
    }

    /// Export validation results to a writer (e.g., stdout).
    pub fn export_validation_results_to_writer<W: Write>(
        &self,
        writer: W,
        rows: &[ValidationResultRow],
    ) -> Result<()> {
        let mut csv_writer = csv::Writer::from_writer(writer);

        for row in rows {
            csv_writer.serialize(row)?;
        }

        csv_writer.flush()?;
        Ok(())
    }

    /// Export block metadata to a CSV file.
    #[allow(dead_code)]
    pub fn export_block_metadata<P: AsRef<Path>>(
        &self,
        path: P,
        rows: &[BlockMetadataRow],
    ) -> Result<()> {
        let file = if self.config.append && path.as_ref().exists() {
            std::fs::OpenOptions::new()
                .append(true)
                .open(path.as_ref())?
        } else {
            std::fs::File::create(path.as_ref())?
        };

        let mut writer = csv::WriterBuilder::new()
            .has_headers(!self.config.append || !path.as_ref().exists())
            .from_writer(file);

        for row in rows {
            writer.serialize(row)?;
        }

        writer.flush()?;
        Ok(())
    }

    /// Export simulation results to a CSV file.
    #[allow(dead_code)]
    pub fn export_simulation_results<P: AsRef<Path>>(
        &self,
        path: P,
        rows: &[SimulationResultRow],
    ) -> Result<()> {
        let file = if self.config.append && path.as_ref().exists() {
            std::fs::OpenOptions::new()
                .append(true)
                .open(path.as_ref())?
        } else {
            std::fs::File::create(path.as_ref())?
        };

        let mut writer = csv::WriterBuilder::new()
            .has_headers(!self.config.append || !path.as_ref().exists())
            .from_writer(file);

        for row in rows {
            writer.serialize(row)?;
        }

        writer.flush()?;
        Ok(())
    }
}

/// Helper to convert an optional i32 to a string representation.
#[allow(dead_code)]
pub fn opt_i32_to_string(val: Option<i32>) -> String {
    val.map(|v| v.to_string()).unwrap_or_default()
}

/// Helper to convert an optional bool to a string representation.
#[allow(dead_code)]
pub fn opt_bool_to_string(val: Option<bool>) -> String {
    val.map(|v| if v { "true" } else { "false" })
        .unwrap_or_default()
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::NamedTempFile;

    #[test]
    fn test_export_validation_results() {
        let exporter = CsvExporter::with_defaults();
        let temp_file = NamedTempFile::new().unwrap();

        let rows = vec![
            ValidationResultRow {
                timestamp: "2024-01-15T10:00:00Z".to_string(),
                block_id: 1,
                binary_path: "/usr/bin/test".to_string(),
                start_address: "0x1000".to_string(),
                end_address: "0x1100".to_string(),
                block_size: 256,
                native_exit_code: "0".to_string(),
                fex_exit_code: "0".to_string(),
                status: "passed".to_string(),
                passed: "true".to_string(),
                execution_time_ms: 123.45,
                error_message: "".to_string(),
                native_flags: "0x246".to_string(),
                fex_flags: "0x246".to_string(),
                flags_match: "true".to_string(),
                register_diff_count: 0,
                memory_diff_count: 0,
            },
            ValidationResultRow {
                timestamp: "2024-01-15T10:00:01Z".to_string(),
                block_id: 2,
                binary_path: "/usr/bin/test".to_string(),
                start_address: "0x2000".to_string(),
                end_address: "0x2050".to_string(),
                block_size: 80,
                native_exit_code: "0".to_string(),
                fex_exit_code: "1".to_string(),
                status: "failed".to_string(),
                passed: "false".to_string(),
                execution_time_ms: 456.78,
                error_message: "Exit code mismatch".to_string(),
                native_flags: "0x246".to_string(),
                fex_flags: "0x242".to_string(),
                flags_match: "false".to_string(),
                register_diff_count: 2,
                memory_diff_count: 1,
            },
        ];

        exporter
            .export_validation_results(temp_file.path(), &rows)
            .unwrap();

        let content = std::fs::read_to_string(temp_file.path()).unwrap();
        assert!(content.contains("timestamp"));
        assert!(content.contains("block_id"));
        assert!(content.contains("/usr/bin/test"));
        assert!(content.contains("passed"));
        assert!(content.contains("failed"));
    }

    #[test]
    fn test_export_to_stdout() {
        let exporter = CsvExporter::with_defaults();
        let mut output = Vec::new();

        let rows = vec![ValidationResultRow {
            timestamp: "2024-01-15T10:00:00Z".to_string(),
            block_id: 1,
            binary_path: "/test".to_string(),
            start_address: "0x1000".to_string(),
            end_address: "0x1100".to_string(),
            block_size: 256,
            native_exit_code: "0".to_string(),
            fex_exit_code: "0".to_string(),
            status: "passed".to_string(),
            passed: "true".to_string(),
            execution_time_ms: 100.0,
            error_message: "".to_string(),
            native_flags: "0x246".to_string(),
            fex_flags: "0x246".to_string(),
            flags_match: "true".to_string(),
            register_diff_count: 0,
            memory_diff_count: 0,
        }];

        exporter
            .export_validation_results_to_writer(&mut output, &rows)
            .unwrap();

        let content = String::from_utf8(output).unwrap();
        assert!(content.contains("block_id"));
        assert!(content.contains("/test"));
    }

    #[test]
    fn test_append_mode() {
        let temp_file = NamedTempFile::new().unwrap();

        let row1 = ValidationResultRow {
            timestamp: "2024-01-15T10:00:00Z".to_string(),
            block_id: 1,
            binary_path: "/test1".to_string(),
            start_address: "0x1000".to_string(),
            end_address: "0x1100".to_string(),
            block_size: 256,
            native_exit_code: "0".to_string(),
            fex_exit_code: "0".to_string(),
            status: "passed".to_string(),
            passed: "true".to_string(),
            execution_time_ms: 100.0,
            error_message: "".to_string(),
            native_flags: "0x246".to_string(),
            fex_flags: "0x246".to_string(),
            flags_match: "true".to_string(),
            register_diff_count: 0,
            memory_diff_count: 0,
        };

        let row2 = ValidationResultRow {
            timestamp: "2024-01-15T10:00:01Z".to_string(),
            block_id: 2,
            binary_path: "/test2".to_string(),
            start_address: "0x2000".to_string(),
            end_address: "0x2100".to_string(),
            block_size: 256,
            native_exit_code: "0".to_string(),
            fex_exit_code: "0".to_string(),
            status: "passed".to_string(),
            passed: "true".to_string(),
            execution_time_ms: 100.0,
            error_message: "".to_string(),
            native_flags: "0x246".to_string(),
            fex_flags: "0x246".to_string(),
            flags_match: "true".to_string(),
            register_diff_count: 0,
            memory_diff_count: 0,
        };

        // First write
        let exporter1 = CsvExporter::with_defaults();
        exporter1
            .export_validation_results(temp_file.path(), &[row1])
            .unwrap();

        // Append second row
        let exporter2 = CsvExporter::new(CsvExportConfig {
            append: true,
            ..Default::default()
        });
        exporter2
            .export_validation_results(temp_file.path(), &[row2])
            .unwrap();

        let content = std::fs::read_to_string(temp_file.path()).unwrap();
        assert!(content.contains("/test1"));
        assert!(content.contains("/test2"));
    }
}
