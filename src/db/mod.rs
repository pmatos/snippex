use anyhow::Result;
use rusqlite::{params, Connection};
use serde::{Deserialize, Serialize};
use std::path::Path;

use crate::analyzer::BlockAnalysis;

#[cfg(test)]
mod tests;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BinaryInfo {
    pub path: String,
    pub size: u64,
    pub hash: String,
    pub format: String,
    pub architecture: String,
    pub endianness: String,
    pub base_address: u64,
    pub entry_point: u64,
}

#[derive(Debug, Clone)]
pub struct ExtractionInfo {
    pub id: i64,
    pub binary_path: String,
    pub binary_hash: String,
    pub binary_format: String,
    pub binary_architecture: String,
    pub binary_base_address: u64,
    pub start_address: u64,
    pub end_address: u64,
    pub assembly_block: Vec<u8>,
    pub created_at: String,
    pub analysis_status: String,
    pub analysis_results: Option<String>,
}

pub struct Database {
    conn: Connection,
}

impl Database {
    pub fn new(path: &Path) -> Result<Self> {
        let conn = Connection::open(path).map_err(|e| {
            anyhow::anyhow!(
                "Failed to open database: {}\n\n\
                 Database path: {}\n\n\
                 Suggestions:\n\
                 • Verify the directory exists: mkdir -p {}\n\
                 • Check write permissions for the database directory\n\
                 • If database is corrupted, try removing it: rm {}\n\
                 • Ensure sufficient disk space is available",
                e,
                path.display(),
                path.parent()
                    .map(|p| p.display().to_string())
                    .unwrap_or_default(),
                path.display()
            )
        })?;
        Ok(Database { conn })
    }

    pub fn init(&mut self) -> Result<()> {
        self.conn.execute(
            "CREATE TABLE IF NOT EXISTS binaries (
                id INTEGER PRIMARY KEY,
                path TEXT NOT NULL,
                size INTEGER NOT NULL,
                hash TEXT NOT NULL UNIQUE,
                format TEXT NOT NULL,
                architecture TEXT NOT NULL,
                endianness TEXT NOT NULL,
                base_address INTEGER NOT NULL DEFAULT 4194304,
                entry_point INTEGER NOT NULL DEFAULT 0,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )",
            [],
        )?;

        self.conn.execute(
            "CREATE TABLE IF NOT EXISTS extractions (
                id INTEGER PRIMARY KEY,
                binary_id INTEGER NOT NULL,
                start_address INTEGER NOT NULL,
                end_address INTEGER NOT NULL,
                assembly_block BLOB NOT NULL,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (binary_id) REFERENCES binaries(id)
            )",
            [],
        )?;

        self.conn.execute(
            "CREATE TABLE IF NOT EXISTS analyses (
                id INTEGER PRIMARY KEY,
                extraction_id INTEGER NOT NULL UNIQUE,
                instructions_count INTEGER NOT NULL,
                live_in_registers TEXT NOT NULL,
                live_out_registers TEXT NOT NULL,
                exit_points TEXT NOT NULL,
                memory_accesses TEXT NOT NULL,
                pointer_registers TEXT DEFAULT '{}',
                analyzed_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (extraction_id) REFERENCES extractions(id)
            )",
            [],
        )?;

        // Migration: Add pointer_registers column if it doesn't exist (for existing databases)
        let _ = self.conn.execute(
            "ALTER TABLE analyses ADD COLUMN pointer_registers TEXT DEFAULT '{}'",
            [],
        );

        self.conn.execute(
            "CREATE TABLE IF NOT EXISTS simulations (
                id INTEGER PRIMARY KEY,
                extraction_id INTEGER NOT NULL,
                analysis_id INTEGER NOT NULL,
                simulation_id TEXT NOT NULL,
                
                -- Input state
                initial_registers TEXT NOT NULL,
                initial_memory TEXT NOT NULL,
                
                -- Output state
                final_registers TEXT NOT NULL,
                final_memory TEXT NOT NULL,
                final_flags INTEGER NOT NULL,
                
                -- Execution metadata
                execution_time_ns INTEGER NOT NULL,
                exit_code INTEGER NOT NULL,
                emulator_used TEXT,
                
                -- Generated files (for debugging)
                assembly_file_path TEXT,
                binary_file_path TEXT,
                
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (extraction_id) REFERENCES extractions(id),
                FOREIGN KEY (analysis_id) REFERENCES analyses(id)
            )",
            [],
        )?;

        // Create indices for frequently queried columns to improve performance
        self.conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_simulations_extraction_id ON simulations(extraction_id)",
            [],
        )?;

        self.conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_simulations_analysis_id ON simulations(analysis_id)",
            [],
        )?;

        self.conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_extractions_binary_id ON extractions(binary_id)",
            [],
        )?;

        self.conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_analyses_extraction_id ON analyses(extraction_id)",
            [],
        )?;

        self.conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_binaries_hash ON binaries(hash)",
            [],
        )?;

        // Validation results cache table
        self.conn.execute(
            "CREATE TABLE IF NOT EXISTS validation_cache (
                id INTEGER PRIMARY KEY,
                extraction_id INTEGER NOT NULL,
                emulator_type TEXT NOT NULL,
                host_architecture TEXT NOT NULL,

                -- Result data
                exit_code INTEGER NOT NULL,
                final_registers TEXT NOT NULL,
                final_memory TEXT NOT NULL,
                final_flags INTEGER NOT NULL,
                execution_time_ns INTEGER NOT NULL,

                -- Cache metadata
                seed INTEGER,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,

                FOREIGN KEY (extraction_id) REFERENCES extractions(id),
                UNIQUE(extraction_id, emulator_type, seed)
            )",
            [],
        )?;

        self.conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_validation_cache_extraction ON validation_cache(extraction_id)",
            [],
        )?;

        // Additional indexes for cache optimization
        self.conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_validation_cache_composite ON validation_cache(extraction_id, emulator_type, seed)",
            [],
        )?;

        self.conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_validation_cache_created ON validation_cache(created_at)",
            [],
        )?;

        self.conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_validation_cache_emulator ON validation_cache(emulator_type)",
            [],
        )?;

        // Migration: Add last_accessed column for LRU eviction
        let _ = self.conn.execute(
            "ALTER TABLE validation_cache ADD COLUMN last_accessed DATETIME DEFAULT CURRENT_TIMESTAMP",
            [],
        );

        self.conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_validation_cache_accessed ON validation_cache(last_accessed)",
            [],
        )?;

        // Batch validation statistics tables
        self.conn.execute(
            "CREATE TABLE IF NOT EXISTS batch_runs (
                id INTEGER PRIMARY KEY,
                started_at DATETIME NOT NULL,
                completed_at DATETIME,
                block_count INTEGER NOT NULL,
                pass_count INTEGER NOT NULL DEFAULT 0,
                fail_count INTEGER NOT NULL DEFAULT 0,
                skip_count INTEGER NOT NULL DEFAULT 0,
                duration_ms INTEGER,
                emulator TEXT,
                description TEXT
            )",
            [],
        )?;

        self.conn.execute(
            "CREATE TABLE IF NOT EXISTS batch_run_details (
                id INTEGER PRIMARY KEY,
                batch_id INTEGER NOT NULL,
                extraction_id INTEGER NOT NULL,
                status TEXT NOT NULL,
                duration_ns INTEGER,
                error_message TEXT,
                FOREIGN KEY (batch_id) REFERENCES batch_runs(id),
                FOREIGN KEY (extraction_id) REFERENCES extractions(id)
            )",
            [],
        )?;

        self.conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_batch_runs_started ON batch_runs(started_at)",
            [],
        )?;

        self.conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_batch_run_details_batch ON batch_run_details(batch_id)",
            [],
        )?;

        self.conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_batch_run_details_extraction ON batch_run_details(extraction_id)",
            [],
        )?;

        // Migration: Add base_address column to existing binaries table if it doesn't exist
        // This uses ALTER TABLE which will fail silently if column already exists
        let _ = self.conn.execute(
            "ALTER TABLE binaries ADD COLUMN base_address INTEGER NOT NULL DEFAULT 4194304",
            [],
        );

        // Migration: Add entry_point column to existing binaries table if it doesn't exist
        let _ = self.conn.execute(
            "ALTER TABLE binaries ADD COLUMN entry_point INTEGER NOT NULL DEFAULT 0",
            [],
        );

        // Metrics snapshots table for tracking validation success over time
        self.conn.execute(
            "CREATE TABLE IF NOT EXISTS metrics_snapshots (
                id INTEGER PRIMARY KEY,
                recorded_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
                total_blocks INTEGER NOT NULL,
                analyzed_blocks INTEGER NOT NULL,
                validated_blocks INTEGER NOT NULL,
                pass_count INTEGER NOT NULL,
                fail_count INTEGER NOT NULL,
                skip_count INTEGER NOT NULL,
                avg_duration_ns INTEGER,
                notes TEXT
            )",
            [],
        )?;

        self.conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_metrics_snapshots_recorded ON metrics_snapshots(recorded_at)",
            [],
        )?;

        // Regression testing baseline table - stores expected results for blocks
        self.conn.execute(
            "CREATE TABLE IF NOT EXISTS expected_results (
                id INTEGER PRIMARY KEY,
                extraction_id INTEGER NOT NULL,
                block_hash TEXT NOT NULL,
                expected_status TEXT NOT NULL,
                expected_registers TEXT,
                expected_flags INTEGER,
                emulator_type TEXT,
                last_verified DATETIME DEFAULT CURRENT_TIMESTAMP,
                notes TEXT,
                FOREIGN KEY (extraction_id) REFERENCES extractions(id),
                UNIQUE(extraction_id, emulator_type)
            )",
            [],
        )?;

        self.conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_expected_results_extraction ON expected_results(extraction_id)",
            [],
        )?;

        self.conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_expected_results_hash ON expected_results(block_hash)",
            [],
        )?;

        // Regression test runs table - tracks each regression test execution
        self.conn.execute(
            "CREATE TABLE IF NOT EXISTS regression_runs (
                id INTEGER PRIMARY KEY,
                run_id TEXT NOT NULL UNIQUE,
                started_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
                completed_at DATETIME,
                total_blocks INTEGER NOT NULL DEFAULT 0,
                pass_count INTEGER NOT NULL DEFAULT 0,
                fail_count INTEGER NOT NULL DEFAULT 0,
                new_pass_count INTEGER NOT NULL DEFAULT 0,
                new_fail_count INTEGER NOT NULL DEFAULT 0,
                emulator_type TEXT,
                baseline_version TEXT,
                notes TEXT
            )",
            [],
        )?;

        self.conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_regression_runs_started ON regression_runs(started_at)",
            [],
        )?;

        // Regression run details - individual block results for each run
        self.conn.execute(
            "CREATE TABLE IF NOT EXISTS regression_run_details (
                id INTEGER PRIMARY KEY,
                run_id TEXT NOT NULL,
                extraction_id INTEGER NOT NULL,
                expected_status TEXT NOT NULL,
                actual_status TEXT NOT NULL,
                is_regression INTEGER NOT NULL DEFAULT 0,
                is_improvement INTEGER NOT NULL DEFAULT 0,
                error_message TEXT,
                FOREIGN KEY (extraction_id) REFERENCES extractions(id)
            )",
            [],
        )?;

        self.conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_regression_details_run ON regression_run_details(run_id)",
            [],
        )?;

        self.conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_regression_details_extraction ON regression_run_details(extraction_id)",
            [],
        )?;

        Ok(())
    }

    pub fn store_extraction(
        &mut self,
        binary_info: &BinaryInfo,
        start_addr: u64,
        end_addr: u64,
        assembly_block: &[u8],
    ) -> Result<()> {
        let tx = self.conn.transaction()?;

        let binary_id = {
            let mut stmt = tx.prepare("SELECT id FROM binaries WHERE hash = ?1")?;

            let existing_id: Option<i64> =
                stmt.query_row([&binary_info.hash], |row| row.get(0)).ok();

            match existing_id {
                Some(id) => id,
                None => {
                    tx.execute(
                        "INSERT INTO binaries (path, size, hash, format, architecture, endianness, base_address, entry_point)
                         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                        params![
                            binary_info.path,
                            binary_info.size as i64,
                            binary_info.hash,
                            binary_info.format,
                            binary_info.architecture,
                            binary_info.endianness,
                            binary_info.base_address as i64,
                            binary_info.entry_point as i64,
                        ],
                    )?;
                    tx.last_insert_rowid()
                }
            }
        };

        tx.execute(
            "INSERT INTO extractions (binary_id, start_address, end_address, assembly_block)
             VALUES (?1, ?2, ?3, ?4)",
            params![
                binary_id,
                start_addr as i64,
                end_addr as i64,
                assembly_block
            ],
        )?;

        tx.commit()?;
        Ok(())
    }

    pub fn list_extractions(&self) -> Result<Vec<ExtractionInfo>> {
        let mut stmt = self.conn.prepare(
            "SELECT b.path, b.hash, b.format, b.architecture, b.base_address,
                    e.start_address, e.end_address, e.assembly_block, e.created_at,
                    e.id,
                    CASE
                        WHEN a.id IS NOT NULL THEN 'analyzed'
                        ELSE 'not analyzed'
                    END as analysis_status,
                    CASE
                        WHEN a.id IS NOT NULL THEN
                            json_object(
                                'instructions', a.instructions_count,
                                'live_in', a.live_in_registers,
                                'live_out', a.live_out_registers
                            )
                        ELSE NULL
                    END as analysis_summary
             FROM extractions e
             JOIN binaries b ON e.binary_id = b.id
             LEFT JOIN analyses a ON e.id = a.extraction_id
             ORDER BY e.created_at DESC",
        )?;

        let extractions = stmt
            .query_map([], |row| {
                Ok(ExtractionInfo {
                    id: row.get(9)?,
                    binary_path: row.get(0)?,
                    binary_hash: row.get(1)?,
                    binary_format: row.get(2)?,
                    binary_architecture: row.get(3)?,
                    binary_base_address: row.get::<_, i64>(4)? as u64,
                    start_address: row.get::<_, i64>(5)? as u64,
                    end_address: row.get::<_, i64>(6)? as u64,
                    assembly_block: row.get(7)?,
                    created_at: row.get(8)?,
                    analysis_status: row.get(10)?,
                    analysis_results: row.get(11)?,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;

        Ok(extractions)
    }

    pub fn remove_extraction(
        &mut self,
        start_addr: u64,
        end_addr: u64,
        binary_hash: &str,
    ) -> Result<()> {
        let tx = self.conn.transaction()?;

        // Find the binary_id for the given hash
        let binary_id: i64 = tx.query_row(
            "SELECT id FROM binaries WHERE hash = ?1",
            params![binary_hash],
            |row| row.get(0),
        )?;

        // Delete the extraction
        let affected = tx.execute(
            "DELETE FROM extractions
             WHERE binary_id = ?1 AND start_address = ?2 AND end_address = ?3",
            params![binary_id, start_addr as i64, end_addr as i64],
        )?;

        if affected == 0 {
            return Err(anyhow::anyhow!("No matching extraction found"));
        }

        // Check if this was the last extraction for this binary
        let remaining_count: i64 = tx.query_row(
            "SELECT COUNT(*) FROM extractions WHERE binary_id = ?1",
            params![binary_id],
            |row| row.get(0),
        )?;

        // If no more extractions for this binary, remove the binary entry too
        if remaining_count == 0 {
            tx.execute("DELETE FROM binaries WHERE id = ?1", params![binary_id])?;
        }

        tx.commit()?;
        Ok(())
    }

    pub fn remove_all_extractions(&mut self) -> Result<usize> {
        let tx = self.conn.transaction()?;

        // Count extractions before deletion
        let count: usize = tx.query_row("SELECT COUNT(*) FROM extractions", [], |row| {
            row.get::<_, i64>(0)
        })? as usize;

        // Delete in correct order due to foreign key constraints:
        // 1. Delete all analyses first (references extractions)
        tx.execute("DELETE FROM analyses", [])?;

        // 2. Delete all extractions (references binaries)
        tx.execute("DELETE FROM extractions", [])?;

        // 3. Delete all binaries (no dependencies)
        tx.execute("DELETE FROM binaries", [])?;

        tx.commit()?;
        Ok(count)
    }

    pub fn store_analysis(
        &mut self,
        start_addr: u64,
        end_addr: u64,
        binary_hash: &str,
        analysis: &BlockAnalysis,
    ) -> Result<()> {
        let tx = self.conn.transaction()?;

        // Find the extraction_id
        let extraction_id: i64 = tx.query_row(
            "SELECT e.id FROM extractions e
             JOIN binaries b ON e.binary_id = b.id
             WHERE b.hash = ?1 AND e.start_address = ?2 AND e.end_address = ?3",
            params![binary_hash, start_addr as i64, end_addr as i64],
            |row| row.get(0),
        )?;

        // Serialize analysis data
        let live_in_regs: Vec<&str> = analysis
            .live_in_registers
            .iter()
            .map(|s| s.as_str())
            .collect();
        let live_out_regs: Vec<&str> = analysis
            .live_out_registers
            .iter()
            .map(|s| s.as_str())
            .collect();
        let exit_points_json = serde_json::to_string(&analysis.exit_points)?;
        let memory_accesses_json = serde_json::to_string(&analysis.memory_accesses)?;
        let pointer_registers_json = serde_json::to_string(&analysis.pointer_registers)?;

        // Insert or update analysis
        tx.execute(
            "INSERT OR REPLACE INTO analyses
             (extraction_id, instructions_count, live_in_registers, live_out_registers,
              exit_points, memory_accesses, pointer_registers)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                extraction_id,
                analysis.instructions_count as i64,
                live_in_regs.join(","),
                live_out_regs.join(","),
                exit_points_json,
                memory_accesses_json,
                pointer_registers_json,
            ],
        )?;

        tx.commit()?;
        Ok(())
    }

    pub fn store_simulation_result(
        &mut self,
        extraction_id: i64,
        result: &crate::simulator::SimulationResult,
    ) -> Result<()> {
        let tx = self.conn.transaction()?;

        // Find the analysis_id for this extraction
        let analysis_id: i64 = tx.query_row(
            "SELECT id FROM analyses WHERE extraction_id = ?1",
            params![extraction_id],
            |row| row.get(0),
        )?;

        // Serialize state data
        let initial_registers = serde_json::to_string(&result.initial_state.registers)?;
        let initial_memory = serde_json::to_string(&result.initial_state.memory_locations)?;
        let final_registers = serde_json::to_string(&result.final_state.registers)?;
        let final_memory = serde_json::to_string(&result.final_state.memory_locations)?;

        // Insert simulation result
        tx.execute(
            "INSERT INTO simulations (
                extraction_id, analysis_id, simulation_id,
                initial_registers, initial_memory,
                final_registers, final_memory, final_flags,
                execution_time_ns, exit_code, emulator_used,
                assembly_file_path, binary_file_path
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)",
            params![
                extraction_id,
                analysis_id,
                result.simulation_id,
                initial_registers,
                initial_memory,
                final_registers,
                final_memory,
                result.final_state.flags as i64,
                result.execution_time.as_nanos() as i64,
                result.exit_code,
                result.emulator_used,
                result.assembly_file_path,
                result.binary_file_path,
            ],
        )?;

        tx.commit()?;
        Ok(())
    }

    pub fn load_block_analysis(
        &self,
        extraction_id: i64,
    ) -> Result<Option<crate::analyzer::BlockAnalysis>> {
        let mut stmt = self.conn.prepare(
            "SELECT instructions_count, live_in_registers, live_out_registers,
                    exit_points, memory_accesses, COALESCE(pointer_registers, '{}')
             FROM analyses WHERE extraction_id = ?1",
        )?;

        let result = stmt.query_row(params![extraction_id], |row| {
            let instructions_count: i64 = row.get(0)?;
            let live_in_str: String = row.get(1)?;
            let live_out_str: String = row.get(2)?;
            let exit_points_json: String = row.get(3)?;
            let memory_accesses_json: String = row.get(4)?;
            let pointer_registers_json: String = row.get(5)?;

            Ok((
                instructions_count,
                live_in_str,
                live_out_str,
                exit_points_json,
                memory_accesses_json,
                pointer_registers_json,
            ))
        });

        match result {
            Ok((
                instructions_count,
                live_in_str,
                live_out_str,
                exit_points_json,
                memory_accesses_json,
                pointer_registers_json,
            )) => {
                let live_in_registers = live_in_str
                    .split(',')
                    .filter(|s| !s.is_empty())
                    .map(|s| s.to_string())
                    .collect();

                let live_out_registers = live_out_str
                    .split(',')
                    .filter(|s| !s.is_empty())
                    .map(|s| s.to_string())
                    .collect();

                let exit_points = serde_json::from_str(&exit_points_json)
                    .map_err(|e| anyhow::anyhow!("Failed to parse exit points: {}", e))?;

                let memory_accesses = serde_json::from_str(&memory_accesses_json)
                    .map_err(|e| anyhow::anyhow!("Failed to parse memory accesses: {}", e))?;

                let pointer_registers =
                    serde_json::from_str(&pointer_registers_json).unwrap_or_default();

                Ok(Some(crate::analyzer::BlockAnalysis {
                    instructions_count: instructions_count as usize,
                    live_in_registers,
                    live_out_registers,
                    exit_points,
                    memory_accesses,
                    pointer_registers,
                }))
            }
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    pub fn get_binary_by_hash(&self, hash: &str) -> Result<BinaryInfo> {
        let mut stmt = self.conn.prepare(
            "SELECT path, size, hash, format, architecture, endianness, base_address, entry_point
             FROM binaries WHERE hash = ?1",
        )?;

        let binary_info = stmt.query_row(params![hash], |row| {
            Ok(BinaryInfo {
                path: row.get(0)?,
                size: row.get::<_, i64>(1)? as u64,
                hash: row.get(2)?,
                format: row.get(3)?,
                architecture: row.get(4)?,
                endianness: row.get(5)?,
                base_address: row.get::<_, i64>(6)? as u64,
                entry_point: row.get::<_, i64>(7)? as u64,
            })
        })?;

        Ok(binary_info)
    }

    pub fn get_simulations_for_extraction(
        &self,
        extraction_id: i64,
    ) -> Result<Vec<crate::simulator::SimulationResult>> {
        let mut stmt = self.conn.prepare(
            "SELECT simulation_id, initial_registers, initial_memory,
                    final_registers, final_memory, final_flags,
                    execution_time_ns, exit_code, emulator_used,
                    assembly_file_path, binary_file_path
             FROM simulations WHERE extraction_id = ?1",
        )?;

        let simulation_iter = stmt.query_map(params![extraction_id], |row| {
            let simulation_id: String = row.get(0)?;
            let initial_registers_json: String = row.get(1)?;
            let initial_memory_json: String = row.get(2)?;
            let final_registers_json: String = row.get(3)?;
            let final_memory_json: String = row.get(4)?;
            let final_flags: u64 = row.get::<_, i64>(5)? as u64;
            let execution_time_ns: i64 = row.get(6)?;
            let exit_code: i32 = row.get(7)?;
            let emulator_used: Option<String> = row.get(8)?;
            let assembly_file_path: Option<String> = row.get(9)?;
            let binary_file_path: Option<String> = row.get(10)?;

            Ok((
                simulation_id,
                initial_registers_json,
                initial_memory_json,
                final_registers_json,
                final_memory_json,
                final_flags,
                execution_time_ns,
                exit_code,
                emulator_used,
                assembly_file_path,
                binary_file_path,
            ))
        })?;

        let mut simulations = Vec::new();
        for simulation_result in simulation_iter {
            let (
                simulation_id,
                initial_registers_json,
                initial_memory_json,
                final_registers_json,
                final_memory_json,
                final_flags,
                execution_time_ns,
                exit_code,
                emulator_used,
                assembly_file_path,
                binary_file_path,
            ) = simulation_result?;

            let initial_registers =
                serde_json::from_str(&initial_registers_json).map_err(|_e| {
                    rusqlite::Error::InvalidColumnType(
                        0,
                        "initial_registers".to_string(),
                        rusqlite::types::Type::Text,
                    )
                })?;
            let initial_memory = serde_json::from_str(&initial_memory_json).map_err(|_e| {
                rusqlite::Error::InvalidColumnType(
                    0,
                    "initial_memory".to_string(),
                    rusqlite::types::Type::Text,
                )
            })?;
            let final_registers = serde_json::from_str(&final_registers_json).map_err(|_e| {
                rusqlite::Error::InvalidColumnType(
                    0,
                    "final_registers".to_string(),
                    rusqlite::types::Type::Text,
                )
            })?;
            let final_memory = serde_json::from_str(&final_memory_json).map_err(|_e| {
                rusqlite::Error::InvalidColumnType(
                    0,
                    "final_memory".to_string(),
                    rusqlite::types::Type::Text,
                )
            })?;

            let initial_state = crate::simulator::InitialState {
                registers: initial_registers,
                memory_locations: initial_memory,
                stack_setup: Vec::new(), // Not stored in DB for now
            };

            let final_state = crate::simulator::FinalState {
                registers: final_registers,
                memory_locations: final_memory,
                flags: final_flags,
            };

            let simulation = crate::simulator::SimulationResult {
                simulation_id,
                initial_state,
                final_state,
                execution_time: std::time::Duration::from_nanos(execution_time_ns as u64),
                exit_code,
                emulator_used,
                assembly_file_path,
                binary_file_path,
            };

            simulations.push(simulation);
        }

        Ok(simulations)
    }

    pub fn store_binary_info(&mut self, binary_info: &BinaryInfo) -> Result<()> {
        self.conn.execute(
            "INSERT OR IGNORE INTO binaries (path, size, hash, format, architecture, endianness, base_address, entry_point)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                binary_info.path,
                binary_info.size as i64,
                binary_info.hash,
                binary_info.format,
                binary_info.architecture,
                binary_info.endianness,
                binary_info.base_address as i64,
                binary_info.entry_point as i64,
            ],
        )?;
        Ok(())
    }

    /// Stores a validation result in the cache.
    pub fn store_validation_cache(
        &mut self,
        extraction_id: i64,
        emulator_type: &str,
        host_architecture: &str,
        result: &crate::simulator::SimulationResult,
        seed: Option<u64>,
    ) -> Result<()> {
        let final_registers = serde_json::to_string(&result.final_state.registers)?;
        let final_memory = serde_json::to_string(&result.final_state.memory_locations)?;

        self.conn.execute(
            "INSERT OR REPLACE INTO validation_cache (
                extraction_id, emulator_type, host_architecture,
                exit_code, final_registers, final_memory, final_flags, execution_time_ns,
                seed
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            params![
                extraction_id,
                emulator_type,
                host_architecture,
                result.exit_code,
                final_registers,
                final_memory,
                result.final_state.flags as i64,
                result.execution_time.as_nanos() as i64,
                seed.map(|s| s as i64),
            ],
        )?;
        Ok(())
    }

    /// Retrieves a cached validation result if available and not expired.
    /// Updates last_accessed timestamp on cache hit for LRU eviction.
    pub fn get_validation_cache(
        &self,
        extraction_id: i64,
        emulator_type: &str,
        seed: Option<u64>,
        ttl_days: u32,
    ) -> Result<Option<CachedValidationResult>> {
        let ttl_seconds = ttl_days as i64 * 24 * 60 * 60;

        let mut stmt = self.conn.prepare(
            "SELECT id, exit_code, final_registers, final_memory, final_flags, execution_time_ns,
                    host_architecture, created_at
             FROM validation_cache
             WHERE extraction_id = ?1
               AND emulator_type = ?2
               AND ((?3 IS NULL AND seed IS NULL) OR seed = ?3)
               AND julianday('now') - julianday(created_at) < ?4 / 86400.0",
        )?;

        let result = stmt.query_row(
            params![
                extraction_id,
                emulator_type,
                seed.map(|s| s as i64),
                ttl_seconds,
            ],
            |row| {
                let id: i64 = row.get(0)?;
                let exit_code: i32 = row.get(1)?;
                let final_registers_json: String = row.get(2)?;
                let final_memory_json: String = row.get(3)?;
                let final_flags: i64 = row.get(4)?;
                let execution_time_ns: i64 = row.get(5)?;
                let host_architecture: String = row.get(6)?;
                let created_at: String = row.get(7)?;

                Ok((
                    id,
                    exit_code,
                    final_registers_json,
                    final_memory_json,
                    final_flags,
                    execution_time_ns,
                    host_architecture,
                    created_at,
                ))
            },
        );

        match result {
            Ok((
                cache_id,
                exit_code,
                final_registers_json,
                final_memory_json,
                final_flags,
                execution_time_ns,
                host_architecture,
                created_at,
            )) => {
                // Update last_accessed timestamp for LRU tracking
                let _ = self.conn.execute(
                    "UPDATE validation_cache SET last_accessed = CURRENT_TIMESTAMP WHERE id = ?1",
                    params![cache_id],
                );

                let final_registers = serde_json::from_str(&final_registers_json)
                    .map_err(|e| anyhow::anyhow!("Failed to parse cached registers: {}", e))?;
                let final_memory = serde_json::from_str(&final_memory_json)
                    .map_err(|e| anyhow::anyhow!("Failed to parse cached memory: {}", e))?;

                Ok(Some(CachedValidationResult {
                    exit_code,
                    final_state: crate::simulator::FinalState {
                        registers: final_registers,
                        memory_locations: final_memory,
                        flags: final_flags as u64,
                    },
                    execution_time: std::time::Duration::from_nanos(execution_time_ns as u64),
                    host_architecture,
                    cached_at: created_at,
                }))
            }
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    /// Clears all validation cache entries.
    pub fn clear_validation_cache(&mut self) -> Result<usize> {
        let count: usize =
            self.conn
                .query_row("SELECT COUNT(*) FROM validation_cache", [], |row| {
                    row.get::<_, i64>(0)
                })? as usize;

        self.conn.execute("DELETE FROM validation_cache", [])?;
        Ok(count)
    }

    /// Clears validation cache entries older than the specified TTL.
    pub fn clear_expired_validation_cache(&mut self, ttl_days: u32) -> Result<usize> {
        let ttl_seconds = ttl_days as i64 * 24 * 60 * 60;

        let count = self.conn.execute(
            "DELETE FROM validation_cache
             WHERE julianday('now') - julianday(created_at) >= ?1 / 86400.0",
            params![ttl_seconds],
        )?;

        Ok(count)
    }

    /// Gets cache statistics.
    pub fn get_validation_cache_stats(&self) -> Result<ValidationCacheStats> {
        let total: i64 =
            self.conn
                .query_row("SELECT COUNT(*) FROM validation_cache", [], |row| {
                    row.get(0)
                })?;

        let native_count: i64 = self.conn.query_row(
            "SELECT COUNT(*) FROM validation_cache WHERE emulator_type = 'native'",
            [],
            |row| row.get(0),
        )?;

        let fex_count: i64 = self.conn.query_row(
            "SELECT COUNT(*) FROM validation_cache WHERE emulator_type = 'fex-emu'",
            [],
            |row| row.get(0),
        )?;

        let oldest: Option<String> = self
            .conn
            .query_row("SELECT MIN(created_at) FROM validation_cache", [], |row| {
                row.get(0)
            })
            .ok();

        let newest: Option<String> = self
            .conn
            .query_row("SELECT MAX(created_at) FROM validation_cache", [], |row| {
                row.get(0)
            })
            .ok();

        Ok(ValidationCacheStats {
            total_entries: total as usize,
            native_entries: native_count as usize,
            fex_entries: fex_count as usize,
            oldest_entry: oldest,
            newest_entry: newest,
            age_distribution: None,
            estimated_size_bytes: None,
        })
    }

    /// Gets detailed cache statistics including age distribution.
    pub fn get_validation_cache_stats_detailed(&self) -> Result<ValidationCacheStats> {
        let mut stats = self.get_validation_cache_stats()?;

        // Calculate age distribution (buckets: <1d, 1-7d, 7-30d, >30d)
        let under_1d: i64 = self.conn.query_row(
            "SELECT COUNT(*) FROM validation_cache WHERE julianday('now') - julianday(created_at) < 1",
            [],
            |row| row.get(0),
        )?;

        let from_1d_to_7d: i64 = self.conn.query_row(
            "SELECT COUNT(*) FROM validation_cache
             WHERE julianday('now') - julianday(created_at) >= 1
               AND julianday('now') - julianday(created_at) < 7",
            [],
            |row| row.get(0),
        )?;

        let from_7d_to_30d: i64 = self.conn.query_row(
            "SELECT COUNT(*) FROM validation_cache
             WHERE julianday('now') - julianday(created_at) >= 7
               AND julianday('now') - julianday(created_at) < 30",
            [],
            |row| row.get(0),
        )?;

        let over_30d: i64 = self.conn.query_row(
            "SELECT COUNT(*) FROM validation_cache WHERE julianday('now') - julianday(created_at) >= 30",
            [],
            |row| row.get(0),
        )?;

        stats.age_distribution = Some(CacheAgeDistribution {
            under_1_day: under_1d as usize,
            from_1_to_7_days: from_1d_to_7d as usize,
            from_7_to_30_days: from_7d_to_30d as usize,
            over_30_days: over_30d as usize,
        });

        // Estimate cache size (approximate - based on average row size)
        let avg_row_size: i64 = self.conn.query_row(
            "SELECT COALESCE(AVG(LENGTH(final_registers) + LENGTH(final_memory)), 0) FROM validation_cache",
            [],
            |row| row.get(0),
        ).unwrap_or(0);

        stats.estimated_size_bytes =
            Some((stats.total_entries as i64 * (avg_row_size + 100)) as usize);

        Ok(stats)
    }

    /// Evicts least recently used cache entries to maintain max size.
    /// Returns the number of entries evicted.
    pub fn evict_lru_cache(&mut self, max_entries: usize) -> Result<usize> {
        let current_count: i64 =
            self.conn
                .query_row("SELECT COUNT(*) FROM validation_cache", [], |row| {
                    row.get(0)
                })?;

        if current_count as usize <= max_entries {
            return Ok(0);
        }

        let to_evict = current_count as usize - max_entries;

        // Delete the least recently accessed entries
        let deleted = self.conn.execute(
            "DELETE FROM validation_cache WHERE id IN (
                SELECT id FROM validation_cache
                ORDER BY COALESCE(last_accessed, created_at) ASC
                LIMIT ?1
            )",
            params![to_evict as i64],
        )?;

        Ok(deleted)
    }

    /// Pre-fetches cache entries for a batch of extraction IDs.
    /// Returns a map of (extraction_id, emulator_type) -> cached result.
    #[allow(dead_code)]
    pub fn prefetch_cache_batch(
        &self,
        extraction_ids: &[i64],
        emulator_type: &str,
        seed: Option<u64>,
        ttl_days: u32,
    ) -> Result<std::collections::HashMap<i64, CachedValidationResult>> {
        use std::collections::HashMap;

        if extraction_ids.is_empty() {
            return Ok(HashMap::new());
        }

        let ttl_seconds = ttl_days as i64 * 24 * 60 * 60;

        // Build IN clause placeholders
        let placeholders: Vec<String> = extraction_ids.iter().map(|_| "?".to_string()).collect();
        let in_clause = placeholders.join(",");

        let query = format!(
            "SELECT id, extraction_id, exit_code, final_registers, final_memory, final_flags,
                    execution_time_ns, host_architecture, created_at
             FROM validation_cache
             WHERE extraction_id IN ({})
               AND emulator_type = ?
               AND ((?{} IS NULL AND seed IS NULL) OR seed = ?{})
               AND julianday('now') - julianday(created_at) < ? / 86400.0",
            in_clause,
            placeholders.len() + 2,
            placeholders.len() + 2
        );

        let mut stmt = self.conn.prepare(&query)?;

        // Build params: extraction_ids... + emulator_type + seed + seed + ttl_seconds
        let mut params_vec: Vec<Box<dyn rusqlite::ToSql>> = extraction_ids
            .iter()
            .map(|id| Box::new(*id) as Box<dyn rusqlite::ToSql>)
            .collect();
        params_vec.push(Box::new(emulator_type.to_string()));
        params_vec.push(Box::new(seed.map(|s| s as i64)));
        params_vec.push(Box::new(seed.map(|s| s as i64)));
        params_vec.push(Box::new(ttl_seconds));

        let params_slice: Vec<&dyn rusqlite::ToSql> =
            params_vec.iter().map(|p| p.as_ref()).collect();

        let mut results = HashMap::new();
        let mut cache_ids = Vec::new();

        {
            let mut rows = stmt.query(params_slice.as_slice())?;

            while let Some(row) = rows.next()? {
                let cache_id: i64 = row.get(0)?;
                let extraction_id: i64 = row.get(1)?;
                let exit_code: i32 = row.get(2)?;
                let final_registers_json: String = row.get(3)?;
                let final_memory_json: String = row.get(4)?;
                let final_flags: i64 = row.get(5)?;
                let execution_time_ns: i64 = row.get(6)?;
                let host_architecture: String = row.get(7)?;
                let created_at: String = row.get(8)?;

                let final_registers: std::collections::HashMap<String, u64> =
                    serde_json::from_str(&final_registers_json).unwrap_or_default();
                let final_memory: std::collections::HashMap<u64, Vec<u8>> =
                    serde_json::from_str(&final_memory_json).unwrap_or_default();

                let cached = CachedValidationResult {
                    exit_code,
                    final_state: crate::simulator::FinalState {
                        registers: final_registers,
                        memory_locations: final_memory,
                        flags: final_flags as u64,
                    },
                    execution_time: std::time::Duration::from_nanos(execution_time_ns as u64),
                    host_architecture,
                    cached_at: created_at,
                };

                results.insert(extraction_id, cached);
                cache_ids.push(cache_id);
            }
        }

        // Update last_accessed for all fetched entries
        if !cache_ids.is_empty() {
            let id_placeholders: Vec<String> = cache_ids.iter().map(|_| "?".to_string()).collect();
            let update_query = format!(
                "UPDATE validation_cache SET last_accessed = CURRENT_TIMESTAMP WHERE id IN ({})",
                id_placeholders.join(",")
            );
            let mut update_stmt = self.conn.prepare(&update_query)?;
            let update_params: Vec<&dyn rusqlite::ToSql> = cache_ids
                .iter()
                .map(|id| id as &dyn rusqlite::ToSql)
                .collect();
            let _ = update_stmt.execute(update_params.as_slice());
        }

        Ok(results)
    }

    /// Gets the number of unique extractions in the cache.
    #[allow(dead_code)]
    pub fn get_cache_extraction_count(&self) -> Result<usize> {
        let count: i64 = self.conn.query_row(
            "SELECT COUNT(DISTINCT extraction_id) FROM validation_cache",
            [],
            |row| row.get(0),
        )?;
        Ok(count as usize)
    }

    // ==================== Batch Statistics Methods ====================

    /// Starts a new batch run and returns its ID.
    #[allow(dead_code)]
    pub fn start_batch_run(
        &mut self,
        block_count: usize,
        emulator: Option<&str>,
        description: Option<&str>,
    ) -> Result<i64> {
        self.conn.execute(
            "INSERT INTO batch_runs (started_at, block_count, emulator, description)
             VALUES (CURRENT_TIMESTAMP, ?1, ?2, ?3)",
            params![block_count as i64, emulator, description],
        )?;
        Ok(self.conn.last_insert_rowid())
    }

    /// Completes a batch run with final statistics.
    #[allow(dead_code)]
    pub fn complete_batch_run(
        &mut self,
        batch_id: i64,
        pass_count: usize,
        fail_count: usize,
        skip_count: usize,
        duration_ms: u64,
    ) -> Result<()> {
        self.conn.execute(
            "UPDATE batch_runs SET
                completed_at = CURRENT_TIMESTAMP,
                pass_count = ?2,
                fail_count = ?3,
                skip_count = ?4,
                duration_ms = ?5
             WHERE id = ?1",
            params![
                batch_id,
                pass_count as i64,
                fail_count as i64,
                skip_count as i64,
                duration_ms as i64
            ],
        )?;
        Ok(())
    }

    /// Records a single block result in a batch run.
    #[allow(dead_code)]
    pub fn record_batch_block_result(
        &mut self,
        batch_id: i64,
        extraction_id: i64,
        status: &str,
        duration_ns: Option<u64>,
        error_message: Option<&str>,
    ) -> Result<()> {
        self.conn.execute(
            "INSERT INTO batch_run_details (batch_id, extraction_id, status, duration_ns, error_message)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                batch_id,
                extraction_id,
                status,
                duration_ns.map(|d| d as i64),
                error_message
            ],
        )?;
        Ok(())
    }

    /// Gets summary statistics across all batch runs.
    pub fn get_batch_summary_stats(&self) -> Result<BatchSummaryStats> {
        let total_runs: i64 = self.conn.query_row(
            "SELECT COUNT(*) FROM batch_runs WHERE completed_at IS NOT NULL",
            [],
            |row| row.get(0),
        )?;

        let total_blocks: i64 = self.conn.query_row(
            "SELECT COALESCE(SUM(block_count), 0) FROM batch_runs WHERE completed_at IS NOT NULL",
            [],
            |row| row.get(0),
        )?;

        let total_pass: i64 = self.conn.query_row(
            "SELECT COALESCE(SUM(pass_count), 0) FROM batch_runs WHERE completed_at IS NOT NULL",
            [],
            |row| row.get(0),
        )?;

        let total_fail: i64 = self.conn.query_row(
            "SELECT COALESCE(SUM(fail_count), 0) FROM batch_runs WHERE completed_at IS NOT NULL",
            [],
            |row| row.get(0),
        )?;

        let total_skip: i64 = self.conn.query_row(
            "SELECT COALESCE(SUM(skip_count), 0) FROM batch_runs WHERE completed_at IS NOT NULL",
            [],
            |row| row.get(0),
        )?;

        let avg_duration_ms: f64 = self.conn.query_row(
            "SELECT COALESCE(AVG(duration_ms), 0) FROM batch_runs WHERE completed_at IS NOT NULL",
            [],
            |row| row.get(0),
        )?;

        let pass_rate = if total_blocks > 0 {
            (total_pass as f64 / total_blocks as f64) * 100.0
        } else {
            0.0
        };

        Ok(BatchSummaryStats {
            total_runs: total_runs as usize,
            total_blocks: total_blocks as usize,
            total_pass: total_pass as usize,
            total_fail: total_fail as usize,
            total_skip: total_skip as usize,
            pass_rate,
            avg_duration_ms,
        })
    }

    /// Gets recent batch runs (most recent first).
    pub fn get_recent_batch_runs(&self, limit: usize) -> Result<Vec<BatchRunInfo>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, started_at, completed_at, block_count, pass_count, fail_count,
                    skip_count, duration_ms, emulator, description
             FROM batch_runs
             ORDER BY started_at DESC
             LIMIT ?1",
        )?;

        let runs = stmt
            .query_map(params![limit as i64], |row| {
                Ok(BatchRunInfo {
                    id: row.get(0)?,
                    started_at: row.get(1)?,
                    completed_at: row.get(2)?,
                    block_count: row.get::<_, i64>(3)? as usize,
                    pass_count: row.get::<_, i64>(4)? as usize,
                    fail_count: row.get::<_, i64>(5)? as usize,
                    skip_count: row.get::<_, i64>(6)? as usize,
                    duration_ms: row.get::<_, Option<i64>>(7)?.map(|d| d as u64),
                    emulator: row.get(8)?,
                    description: row.get(9)?,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;

        Ok(runs)
    }

    /// Gets pass rate trends over time (by day).
    pub fn get_pass_rate_trends(&self, days: usize) -> Result<Vec<DailyStats>> {
        let mut stmt = self.conn.prepare(
            "SELECT DATE(started_at) as day,
                    SUM(block_count) as blocks,
                    SUM(pass_count) as passes,
                    SUM(fail_count) as fails
             FROM batch_runs
             WHERE completed_at IS NOT NULL
               AND started_at >= DATE('now', ?1)
             GROUP BY DATE(started_at)
             ORDER BY day ASC",
        )?;

        let offset = format!("-{} days", days);
        let trends = stmt
            .query_map(params![offset], |row| {
                let day: String = row.get(0)?;
                let blocks: i64 = row.get(1)?;
                let passes: i64 = row.get(2)?;
                let fails: i64 = row.get(3)?;
                let pass_rate = if blocks > 0 {
                    (passes as f64 / blocks as f64) * 100.0
                } else {
                    0.0
                };
                Ok(DailyStats {
                    date: day,
                    total_blocks: blocks as usize,
                    pass_count: passes as usize,
                    fail_count: fails as usize,
                    pass_rate,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;

        Ok(trends)
    }

    /// Gets blocks that consistently fail across multiple batch runs.
    pub fn get_consistently_failing_blocks(
        &self,
        min_failures: usize,
    ) -> Result<Vec<FailingBlockInfo>> {
        let mut stmt = self.conn.prepare(
            "SELECT d.extraction_id, COUNT(*) as fail_count,
                    e.start_address, e.end_address, b.path
             FROM batch_run_details d
             JOIN extractions e ON d.extraction_id = e.id
             JOIN binaries b ON e.binary_id = b.id
             WHERE d.status = 'fail'
             GROUP BY d.extraction_id
             HAVING COUNT(*) >= ?1
             ORDER BY fail_count DESC",
        )?;

        let blocks = stmt
            .query_map(params![min_failures as i64], |row| {
                Ok(FailingBlockInfo {
                    extraction_id: row.get(0)?,
                    failure_count: row.get::<_, i64>(1)? as usize,
                    start_address: row.get::<_, i64>(2)? as u64,
                    end_address: row.get::<_, i64>(3)? as u64,
                    binary_path: row.get(4)?,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;

        Ok(blocks)
    }

    /// Gets blocks that intermittently fail (pass sometimes, fail sometimes).
    pub fn get_flaky_blocks(&self, min_runs: usize) -> Result<Vec<FlakyBlockInfo>> {
        let mut stmt = self.conn.prepare(
            "SELECT d.extraction_id,
                    SUM(CASE WHEN d.status = 'pass' THEN 1 ELSE 0 END) as pass_count,
                    SUM(CASE WHEN d.status = 'fail' THEN 1 ELSE 0 END) as fail_count,
                    COUNT(*) as total_runs,
                    e.start_address, e.end_address, b.path
             FROM batch_run_details d
             JOIN extractions e ON d.extraction_id = e.id
             JOIN binaries b ON e.binary_id = b.id
             GROUP BY d.extraction_id
             HAVING COUNT(*) >= ?1
                AND SUM(CASE WHEN d.status = 'pass' THEN 1 ELSE 0 END) > 0
                AND SUM(CASE WHEN d.status = 'fail' THEN 1 ELSE 0 END) > 0
             ORDER BY fail_count DESC",
        )?;

        let blocks = stmt
            .query_map(params![min_runs as i64], |row| {
                let pass_count: i64 = row.get(1)?;
                let fail_count: i64 = row.get(2)?;
                let total_runs: i64 = row.get(3)?;
                let flakiness = if total_runs > 0 {
                    (fail_count as f64 / total_runs as f64) * 100.0
                } else {
                    0.0
                };
                Ok(FlakyBlockInfo {
                    extraction_id: row.get(0)?,
                    pass_count: pass_count as usize,
                    fail_count: fail_count as usize,
                    total_runs: total_runs as usize,
                    flakiness_percent: flakiness,
                    start_address: row.get::<_, i64>(4)? as u64,
                    end_address: row.get::<_, i64>(5)? as u64,
                    binary_path: row.get(6)?,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;

        Ok(blocks)
    }

    /// Gets failure mode distribution (counts by error type).
    pub fn get_failure_modes(&self) -> Result<Vec<FailureModeInfo>> {
        let mut stmt = self.conn.prepare(
            "SELECT
                CASE
                    WHEN error_message LIKE '%register%' THEN 'Register mismatch'
                    WHEN error_message LIKE '%memory%' THEN 'Memory mismatch'
                    WHEN error_message LIKE '%flag%' THEN 'Flag mismatch'
                    WHEN error_message LIKE '%exit%' OR error_message LIKE '%code%' THEN 'Exit code mismatch'
                    WHEN error_message LIKE '%timeout%' THEN 'Timeout'
                    WHEN error_message LIKE '%crash%' OR error_message LIKE '%segfault%' THEN 'Crash'
                    WHEN error_message IS NULL THEN 'Unknown'
                    ELSE 'Other'
                END as failure_mode,
                COUNT(*) as count
             FROM batch_run_details
             WHERE status = 'fail'
             GROUP BY failure_mode
             ORDER BY count DESC",
        )?;

        let modes = stmt
            .query_map([], |row| {
                Ok(FailureModeInfo {
                    mode: row.get(0)?,
                    count: row.get::<_, i64>(1)? as usize,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;

        Ok(modes)
    }

    /// Clears all batch statistics.
    pub fn clear_batch_stats(&mut self) -> Result<usize> {
        let count: i64 = self
            .conn
            .query_row("SELECT COUNT(*) FROM batch_runs", [], |row| row.get(0))?;

        self.conn.execute("DELETE FROM batch_run_details", [])?;
        self.conn.execute("DELETE FROM batch_runs", [])?;

        Ok(count as usize)
    }

    // ==================== Metrics Snapshot Methods ====================

    /// Records a metrics snapshot of the current validation state.
    #[allow(dead_code)]
    pub fn record_metrics_snapshot(&mut self, notes: Option<&str>) -> Result<i64> {
        // Count total extractions
        let total_blocks: i64 = self
            .conn
            .query_row("SELECT COUNT(*) FROM extractions", [], |row| row.get(0))?;

        // Count analyzed blocks
        let analyzed_blocks: i64 = self.conn.query_row(
            "SELECT COUNT(DISTINCT extraction_id) FROM analyses",
            [],
            |row| row.get(0),
        )?;

        // Count blocks with validation cache entries
        let validated_blocks: i64 = self.conn.query_row(
            "SELECT COUNT(DISTINCT extraction_id) FROM validation_cache",
            [],
            |row| row.get(0),
        )?;

        // Count pass/fail from most recent batch runs
        let pass_count: i64 = self.conn.query_row(
            "SELECT COALESCE(SUM(pass_count), 0) FROM batch_runs WHERE completed_at IS NOT NULL",
            [],
            |row| row.get(0),
        )?;

        let fail_count: i64 = self.conn.query_row(
            "SELECT COALESCE(SUM(fail_count), 0) FROM batch_runs WHERE completed_at IS NOT NULL",
            [],
            |row| row.get(0),
        )?;

        let skip_count: i64 = self.conn.query_row(
            "SELECT COALESCE(SUM(skip_count), 0) FROM batch_runs WHERE completed_at IS NOT NULL",
            [],
            |row| row.get(0),
        )?;

        // Calculate average duration
        let avg_duration: Option<i64> = self
            .conn
            .query_row(
                "SELECT AVG(duration_ns) FROM batch_run_details WHERE status = 'pass'",
                [],
                |row| row.get(0),
            )
            .ok();

        self.conn.execute(
            "INSERT INTO metrics_snapshots
             (total_blocks, analyzed_blocks, validated_blocks, pass_count, fail_count, skip_count, avg_duration_ns, notes)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                total_blocks,
                analyzed_blocks,
                validated_blocks,
                pass_count,
                fail_count,
                skip_count,
                avg_duration,
                notes
            ],
        )?;

        Ok(self.conn.last_insert_rowid())
    }

    /// Gets the most recent metrics snapshots.
    #[allow(dead_code)]
    pub fn get_metrics_snapshots(&self, limit: usize) -> Result<Vec<MetricsSnapshot>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, recorded_at, total_blocks, analyzed_blocks, validated_blocks,
                    pass_count, fail_count, skip_count, avg_duration_ns, notes
             FROM metrics_snapshots
             ORDER BY recorded_at DESC
             LIMIT ?1",
        )?;

        let rows = stmt.query_map([limit as i64], |row| {
            Ok(MetricsSnapshot {
                id: row.get(0)?,
                recorded_at: row.get(1)?,
                total_blocks: row.get::<_, i64>(2)? as usize,
                analyzed_blocks: row.get::<_, i64>(3)? as usize,
                validated_blocks: row.get::<_, i64>(4)? as usize,
                pass_count: row.get::<_, i64>(5)? as usize,
                fail_count: row.get::<_, i64>(6)? as usize,
                skip_count: row.get::<_, i64>(7)? as usize,
                avg_duration_ns: row.get::<_, Option<i64>>(8)?.map(|v| v as u64),
                notes: row.get(9)?,
            })
        })?;

        let mut snapshots = Vec::new();
        for row in rows {
            snapshots.push(row?);
        }

        Ok(snapshots)
    }

    /// Gets metrics snapshots within a date range.
    #[allow(dead_code)]
    pub fn get_metrics_snapshots_in_range(
        &self,
        start_date: &str,
        end_date: &str,
    ) -> Result<Vec<MetricsSnapshot>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, recorded_at, total_blocks, analyzed_blocks, validated_blocks,
                    pass_count, fail_count, skip_count, avg_duration_ns, notes
             FROM metrics_snapshots
             WHERE recorded_at >= ?1 AND recorded_at <= ?2
             ORDER BY recorded_at ASC",
        )?;

        let rows = stmt.query_map([start_date, end_date], |row| {
            Ok(MetricsSnapshot {
                id: row.get(0)?,
                recorded_at: row.get(1)?,
                total_blocks: row.get::<_, i64>(2)? as usize,
                analyzed_blocks: row.get::<_, i64>(3)? as usize,
                validated_blocks: row.get::<_, i64>(4)? as usize,
                pass_count: row.get::<_, i64>(5)? as usize,
                fail_count: row.get::<_, i64>(6)? as usize,
                skip_count: row.get::<_, i64>(7)? as usize,
                avg_duration_ns: row.get::<_, Option<i64>>(8)?.map(|v| v as u64),
                notes: row.get(9)?,
            })
        })?;

        let mut snapshots = Vec::new();
        for row in rows {
            snapshots.push(row?);
        }

        Ok(snapshots)
    }

    /// Gets the latest metrics snapshot.
    #[allow(dead_code)]
    pub fn get_latest_metrics_snapshot(&self) -> Result<Option<MetricsSnapshot>> {
        let snapshots = self.get_metrics_snapshots(1)?;
        Ok(snapshots.into_iter().next())
    }

    /// Deletes all metrics snapshots.
    #[allow(dead_code)]
    pub fn clear_metrics_snapshots(&mut self) -> Result<usize> {
        let count: i64 = self
            .conn
            .query_row("SELECT COUNT(*) FROM metrics_snapshots", [], |row| {
                row.get(0)
            })?;

        self.conn.execute("DELETE FROM metrics_snapshots", [])?;

        Ok(count as usize)
    }

    // ========== Regression Testing Methods ==========

    /// Records an expected result baseline for a block.
    #[allow(dead_code)]
    pub fn record_expected_result(
        &mut self,
        extraction_id: i64,
        block_hash: &str,
        expected_status: &str,
        expected_registers: Option<&str>,
        expected_flags: Option<i64>,
        emulator_type: Option<&str>,
        notes: Option<&str>,
    ) -> Result<i64> {
        self.conn.execute(
            "INSERT OR REPLACE INTO expected_results
             (extraction_id, block_hash, expected_status, expected_registers,
              expected_flags, emulator_type, last_verified, notes)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, CURRENT_TIMESTAMP, ?7)",
            params![
                extraction_id,
                block_hash,
                expected_status,
                expected_registers,
                expected_flags,
                emulator_type,
                notes,
            ],
        )?;

        Ok(self.conn.last_insert_rowid())
    }

    /// Gets expected result for an extraction.
    #[allow(dead_code)]
    pub fn get_expected_result(
        &self,
        extraction_id: i64,
        emulator_type: Option<&str>,
    ) -> Result<Option<ExpectedResult>> {
        let query = if emulator_type.is_some() {
            "SELECT id, extraction_id, block_hash, expected_status, expected_registers,
                    expected_flags, emulator_type, last_verified, notes
             FROM expected_results
             WHERE extraction_id = ?1 AND (emulator_type = ?2 OR emulator_type IS NULL)"
        } else {
            "SELECT id, extraction_id, block_hash, expected_status, expected_registers,
                    expected_flags, emulator_type, last_verified, notes
             FROM expected_results
             WHERE extraction_id = ?1 AND emulator_type IS NULL"
        };

        let mut stmt = self.conn.prepare(query)?;

        let result = if let Some(emu) = emulator_type {
            stmt.query_row([extraction_id.to_string(), emu.to_string()], |row| {
                Ok(ExpectedResult {
                    id: row.get(0)?,
                    extraction_id: row.get(1)?,
                    block_hash: row.get(2)?,
                    expected_status: row.get(3)?,
                    expected_registers: row.get(4)?,
                    expected_flags: row.get(5)?,
                    emulator_type: row.get(6)?,
                    last_verified: row.get(7)?,
                    notes: row.get(8)?,
                })
            })
        } else {
            stmt.query_row([extraction_id.to_string()], |row| {
                Ok(ExpectedResult {
                    id: row.get(0)?,
                    extraction_id: row.get(1)?,
                    block_hash: row.get(2)?,
                    expected_status: row.get(3)?,
                    expected_registers: row.get(4)?,
                    expected_flags: row.get(5)?,
                    emulator_type: row.get(6)?,
                    last_verified: row.get(7)?,
                    notes: row.get(8)?,
                })
            })
        };

        match result {
            Ok(r) => Ok(Some(r)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    /// Gets all expected results (baseline).
    #[allow(dead_code)]
    pub fn get_all_expected_results(&self) -> Result<Vec<ExpectedResult>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, extraction_id, block_hash, expected_status, expected_registers,
                    expected_flags, emulator_type, last_verified, notes
             FROM expected_results
             ORDER BY extraction_id",
        )?;

        let rows = stmt.query_map([], |row| {
            Ok(ExpectedResult {
                id: row.get(0)?,
                extraction_id: row.get(1)?,
                block_hash: row.get(2)?,
                expected_status: row.get(3)?,
                expected_registers: row.get(4)?,
                expected_flags: row.get(5)?,
                emulator_type: row.get(6)?,
                last_verified: row.get(7)?,
                notes: row.get(8)?,
            })
        })?;

        let mut results = Vec::new();
        for row in rows {
            results.push(row?);
        }

        Ok(results)
    }

    /// Starts a new regression test run.
    #[allow(dead_code)]
    pub fn start_regression_run(
        &mut self,
        run_id: &str,
        emulator_type: Option<&str>,
        baseline_version: Option<&str>,
    ) -> Result<i64> {
        self.conn.execute(
            "INSERT INTO regression_runs (run_id, emulator_type, baseline_version)
             VALUES (?1, ?2, ?3)",
            params![run_id, emulator_type, baseline_version],
        )?;

        Ok(self.conn.last_insert_rowid())
    }

    /// Records a regression run detail.
    #[allow(dead_code)]
    pub fn record_regression_detail(
        &mut self,
        run_id: &str,
        extraction_id: i64,
        expected_status: &str,
        actual_status: &str,
        is_regression: bool,
        is_improvement: bool,
        error_message: Option<&str>,
    ) -> Result<()> {
        self.conn.execute(
            "INSERT INTO regression_run_details
             (run_id, extraction_id, expected_status, actual_status,
              is_regression, is_improvement, error_message)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                run_id,
                extraction_id,
                expected_status,
                actual_status,
                is_regression as i32,
                is_improvement as i32,
                error_message,
            ],
        )?;

        Ok(())
    }

    /// Completes a regression run with summary stats.
    #[allow(dead_code)]
    pub fn complete_regression_run(
        &mut self,
        run_id: &str,
        total_blocks: usize,
        pass_count: usize,
        fail_count: usize,
        new_pass_count: usize,
        new_fail_count: usize,
        notes: Option<&str>,
    ) -> Result<()> {
        self.conn.execute(
            "UPDATE regression_runs
             SET completed_at = CURRENT_TIMESTAMP,
                 total_blocks = ?2,
                 pass_count = ?3,
                 fail_count = ?4,
                 new_pass_count = ?5,
                 new_fail_count = ?6,
                 notes = ?7
             WHERE run_id = ?1",
            params![
                run_id,
                total_blocks as i64,
                pass_count as i64,
                fail_count as i64,
                new_pass_count as i64,
                new_fail_count as i64,
                notes,
            ],
        )?;

        Ok(())
    }

    /// Gets regression runs, ordered by most recent first.
    #[allow(dead_code)]
    pub fn get_regression_runs(&self, limit: usize) -> Result<Vec<RegressionRun>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, run_id, started_at, completed_at, total_blocks,
                    pass_count, fail_count, new_pass_count, new_fail_count,
                    emulator_type, baseline_version, notes
             FROM regression_runs
             ORDER BY started_at DESC
             LIMIT ?1",
        )?;

        let rows = stmt.query_map([limit as i64], |row| {
            Ok(RegressionRun {
                id: row.get(0)?,
                run_id: row.get(1)?,
                started_at: row.get(2)?,
                completed_at: row.get(3)?,
                total_blocks: row.get::<_, i64>(4)? as usize,
                pass_count: row.get::<_, i64>(5)? as usize,
                fail_count: row.get::<_, i64>(6)? as usize,
                new_pass_count: row.get::<_, i64>(7)? as usize,
                new_fail_count: row.get::<_, i64>(8)? as usize,
                emulator_type: row.get(9)?,
                baseline_version: row.get(10)?,
                notes: row.get(11)?,
            })
        })?;

        let mut runs = Vec::new();
        for row in rows {
            runs.push(row?);
        }

        Ok(runs)
    }

    /// Gets details for a specific regression run.
    #[allow(dead_code)]
    pub fn get_regression_run_details(&self, run_id: &str) -> Result<Vec<RegressionDetail>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, run_id, extraction_id, expected_status, actual_status,
                    is_regression, is_improvement, error_message
             FROM regression_run_details
             WHERE run_id = ?1
             ORDER BY is_regression DESC, is_improvement DESC, extraction_id",
        )?;

        let rows = stmt.query_map([run_id], |row| {
            Ok(RegressionDetail {
                id: row.get(0)?,
                run_id: row.get(1)?,
                extraction_id: row.get(2)?,
                expected_status: row.get(3)?,
                actual_status: row.get(4)?,
                is_regression: row.get::<_, i32>(5)? != 0,
                is_improvement: row.get::<_, i32>(6)? != 0,
                error_message: row.get(7)?,
            })
        })?;

        let mut details = Vec::new();
        for row in rows {
            details.push(row?);
        }

        Ok(details)
    }

    /// Gets only regressions from a run.
    #[allow(dead_code)]
    pub fn get_regressions(&self, run_id: &str) -> Result<Vec<RegressionDetail>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, run_id, extraction_id, expected_status, actual_status,
                    is_regression, is_improvement, error_message
             FROM regression_run_details
             WHERE run_id = ?1 AND is_regression = 1
             ORDER BY extraction_id",
        )?;

        let rows = stmt.query_map([run_id], |row| {
            Ok(RegressionDetail {
                id: row.get(0)?,
                run_id: row.get(1)?,
                extraction_id: row.get(2)?,
                expected_status: row.get(3)?,
                actual_status: row.get(4)?,
                is_regression: true,
                is_improvement: false,
                error_message: row.get(7)?,
            })
        })?;

        let mut details = Vec::new();
        for row in rows {
            details.push(row?);
        }

        Ok(details)
    }

    /// Gets only improvements from a run.
    #[allow(dead_code)]
    pub fn get_improvements(&self, run_id: &str) -> Result<Vec<RegressionDetail>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, run_id, extraction_id, expected_status, actual_status,
                    is_regression, is_improvement, error_message
             FROM regression_run_details
             WHERE run_id = ?1 AND is_improvement = 1
             ORDER BY extraction_id",
        )?;

        let rows = stmt.query_map([run_id], |row| {
            Ok(RegressionDetail {
                id: row.get(0)?,
                run_id: row.get(1)?,
                extraction_id: row.get(2)?,
                expected_status: row.get(3)?,
                actual_status: row.get(4)?,
                is_regression: false,
                is_improvement: true,
                error_message: row.get(7)?,
            })
        })?;

        let mut details = Vec::new();
        for row in rows {
            details.push(row?);
        }

        Ok(details)
    }

    /// Clears expected results (baseline).
    #[allow(dead_code)]
    pub fn clear_expected_results(&mut self) -> Result<usize> {
        let count: i64 = self
            .conn
            .query_row("SELECT COUNT(*) FROM expected_results", [], |row| {
                row.get(0)
            })?;

        self.conn.execute("DELETE FROM expected_results", [])?;

        Ok(count as usize)
    }

    /// Gets count of expected results.
    #[allow(dead_code)]
    pub fn get_expected_results_count(&self) -> Result<usize> {
        let count: i64 = self
            .conn
            .query_row("SELECT COUNT(*) FROM expected_results", [], |row| {
                row.get(0)
            })?;

        Ok(count as usize)
    }
}

/// Cached validation result.
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct CachedValidationResult {
    pub exit_code: i32,
    pub final_state: crate::simulator::FinalState,
    pub execution_time: std::time::Duration,
    pub host_architecture: String,
    pub cached_at: String,
}

/// Statistics about the validation cache.
#[derive(Debug, Clone)]
pub struct ValidationCacheStats {
    pub total_entries: usize,
    pub native_entries: usize,
    pub fex_entries: usize,
    pub oldest_entry: Option<String>,
    pub newest_entry: Option<String>,
    pub age_distribution: Option<CacheAgeDistribution>,
    pub estimated_size_bytes: Option<usize>,
}

/// Age distribution of cache entries.
#[derive(Debug, Clone)]
pub struct CacheAgeDistribution {
    pub under_1_day: usize,
    pub from_1_to_7_days: usize,
    pub from_7_to_30_days: usize,
    pub over_30_days: usize,
}

// ==================== Batch Statistics Structs ====================

/// Summary statistics across all batch runs.
#[derive(Debug, Clone)]
pub struct BatchSummaryStats {
    pub total_runs: usize,
    pub total_blocks: usize,
    pub total_pass: usize,
    pub total_fail: usize,
    pub total_skip: usize,
    pub pass_rate: f64,
    pub avg_duration_ms: f64,
}

/// Information about a single batch run.
#[derive(Debug, Clone)]
pub struct BatchRunInfo {
    pub id: i64,
    pub started_at: String,
    pub completed_at: Option<String>,
    pub block_count: usize,
    pub pass_count: usize,
    pub fail_count: usize,
    pub skip_count: usize,
    pub duration_ms: Option<u64>,
    pub emulator: Option<String>,
    #[allow(dead_code)]
    pub description: Option<String>,
}

/// Daily statistics for trend analysis.
#[derive(Debug, Clone)]
pub struct DailyStats {
    pub date: String,
    pub total_blocks: usize,
    pub pass_count: usize,
    pub fail_count: usize,
    pub pass_rate: f64,
}

/// Information about a consistently failing block.
#[derive(Debug, Clone)]
pub struct FailingBlockInfo {
    pub extraction_id: i64,
    pub failure_count: usize,
    pub start_address: u64,
    pub end_address: u64,
    pub binary_path: String,
}

/// Information about a flaky (intermittently failing) block.
#[derive(Debug, Clone)]
pub struct FlakyBlockInfo {
    pub extraction_id: i64,
    pub pass_count: usize,
    pub fail_count: usize,
    pub total_runs: usize,
    pub flakiness_percent: f64,
    pub start_address: u64,
    pub end_address: u64,
    #[allow(dead_code)]
    pub binary_path: String,
}

/// Failure mode information.
#[derive(Debug, Clone)]
pub struct FailureModeInfo {
    pub mode: String,
    pub count: usize,
}

/// A snapshot of validation metrics at a point in time.
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct MetricsSnapshot {
    pub id: i64,
    pub recorded_at: String,
    pub total_blocks: usize,
    pub analyzed_blocks: usize,
    pub validated_blocks: usize,
    pub pass_count: usize,
    pub fail_count: usize,
    pub skip_count: usize,
    pub avg_duration_ns: Option<u64>,
    pub notes: Option<String>,
}

#[allow(dead_code)]
impl MetricsSnapshot {
    pub fn pass_rate(&self) -> f64 {
        let total = self.pass_count + self.fail_count;
        if total == 0 {
            0.0
        } else {
            (self.pass_count as f64 / total as f64) * 100.0
        }
    }

    pub fn fail_rate(&self) -> f64 {
        let total = self.pass_count + self.fail_count;
        if total == 0 {
            0.0
        } else {
            (self.fail_count as f64 / total as f64) * 100.0
        }
    }
}

/// Expected result baseline for regression testing.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExpectedResult {
    pub id: i64,
    pub extraction_id: i64,
    pub block_hash: String,
    pub expected_status: String,
    pub expected_registers: Option<String>,
    pub expected_flags: Option<i64>,
    pub emulator_type: Option<String>,
    pub last_verified: String,
    pub notes: Option<String>,
}

/// Regression test run summary.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegressionRun {
    pub id: i64,
    pub run_id: String,
    pub started_at: String,
    pub completed_at: Option<String>,
    pub total_blocks: usize,
    pub pass_count: usize,
    pub fail_count: usize,
    pub new_pass_count: usize,
    pub new_fail_count: usize,
    pub emulator_type: Option<String>,
    pub baseline_version: Option<String>,
    pub notes: Option<String>,
}

/// Individual block result in a regression run.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegressionDetail {
    pub id: i64,
    pub run_id: String,
    pub extraction_id: i64,
    pub expected_status: String,
    pub actual_status: String,
    pub is_regression: bool,
    pub is_improvement: bool,
    pub error_message: Option<String>,
}
