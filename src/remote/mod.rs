//! Remote execution infrastructure for cross-architecture testing.
//!
//! This module provides the infrastructure needed to execute simulations
//! on remote machines via SSH, enabling cross-architecture testing where
//! native x86 execution happens on one machine and FEX-Emu execution
//! happens on another.

pub mod executor;
pub mod orchestrator;
pub mod package;
pub mod transfer;

#[allow(unused_imports)]
pub use executor::{ExecutionResult, SSHExecutor};
#[allow(unused_imports)]
pub use orchestrator::RemoteOrchestrator;
#[allow(unused_imports)]
pub use package::{ExecutionPackage, PackageMetadata};
#[allow(unused_imports)]
pub use transfer::{SCPTransfer, TransferResult};
