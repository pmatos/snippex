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
}

#[derive(Debug, Clone)]
pub struct ExtractionInfo {
    pub id: i64,
    pub binary_path: String,
    pub binary_hash: String,
    pub binary_format: String,
    pub binary_architecture: String,
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
        let conn = Connection::open(path)?;
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
                analyzed_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (extraction_id) REFERENCES extractions(id)
            )",
            [],
        )?;

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
                        "INSERT INTO binaries (path, size, hash, format, architecture, endianness)
                         VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                        params![
                            binary_info.path,
                            binary_info.size as i64,
                            binary_info.hash,
                            binary_info.format,
                            binary_info.architecture,
                            binary_info.endianness,
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
            "SELECT b.path, b.hash, b.format, b.architecture, 
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
                    id: row.get(8)?,
                    binary_path: row.get(0)?,
                    binary_hash: row.get(1)?,
                    binary_format: row.get(2)?,
                    binary_architecture: row.get(3)?,
                    start_address: row.get::<_, i64>(4)? as u64,
                    end_address: row.get::<_, i64>(5)? as u64,
                    assembly_block: row.get(6)?,
                    created_at: row.get(7)?,
                    analysis_status: row.get(9)?,
                    analysis_results: row.get(10)?,
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

        // Insert or update analysis
        tx.execute(
            "INSERT OR REPLACE INTO analyses
             (extraction_id, instructions_count, live_in_registers, live_out_registers,
              exit_points, memory_accesses)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                extraction_id,
                analysis.instructions_count as i64,
                live_in_regs.join(","),
                live_out_regs.join(","),
                exit_points_json,
                memory_accesses_json,
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
                    exit_points, memory_accesses
             FROM analyses WHERE extraction_id = ?1",
        )?;

        let result = stmt.query_row(params![extraction_id], |row| {
            let instructions_count: i64 = row.get(0)?;
            let live_in_str: String = row.get(1)?;
            let live_out_str: String = row.get(2)?;
            let exit_points_json: String = row.get(3)?;
            let memory_accesses_json: String = row.get(4)?;

            Ok((
                instructions_count,
                live_in_str,
                live_out_str,
                exit_points_json,
                memory_accesses_json,
            ))
        });

        match result {
            Ok((
                instructions_count,
                live_in_str,
                live_out_str,
                exit_points_json,
                memory_accesses_json,
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

                Ok(Some(crate::analyzer::BlockAnalysis {
                    instructions_count: instructions_count as usize,
                    live_in_registers,
                    live_out_registers,
                    exit_points,
                    memory_accesses,
                }))
            }
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    pub fn get_binary_by_hash(&self, hash: &str) -> Result<BinaryInfo> {
        let mut stmt = self.conn.prepare(
            "SELECT path, size, hash, format, architecture, endianness
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
            "INSERT OR IGNORE INTO binaries (path, size, hash, format, architecture, endianness)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                binary_info.path,
                binary_info.size as i64,
                binary_info.hash,
                binary_info.format,
                binary_info.architecture,
                binary_info.endianness,
            ],
        )?;
        Ok(())
    }
}
