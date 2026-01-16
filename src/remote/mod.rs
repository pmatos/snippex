//! Remote execution infrastructure for cross-architecture testing.
//!
//! This module provides the infrastructure needed to execute simulations
//! on remote machines via SSH, enabling cross-architecture testing where
//! native x86 execution happens on one machine and FEX-Emu execution
//! happens on another.

pub mod diagnostics;
pub mod executor;
pub mod orchestrator;
pub mod package;
pub mod retry;
pub mod transfer;

#[allow(unused_imports)]
pub use diagnostics::{
    diagnose_remote_execution_failure, verify_simulation_dependencies, verify_snippex_installation,
};
#[allow(unused_imports)]
pub use executor::{ExecutionResult, SSHExecutor};
#[allow(unused_imports)]
pub use orchestrator::RemoteOrchestrator;
#[allow(unused_imports)]
pub use package::{ExecutionPackage, PackageMetadata};
#[allow(unused_imports)]
pub use retry::{diagnose_ssh_error, retry_with_backoff, RetryConfig};
#[allow(unused_imports)]
pub use transfer::{SCPTransfer, TransferResult};
