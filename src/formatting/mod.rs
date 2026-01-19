//! Formatting utilities for output display.
//!
//! This module provides formatters for displaying comparison results,
//! register diffs, memory dumps, and other output.

pub mod diff;
pub mod hexdiff;

pub use diff::RegisterDiffFormatter;
pub use hexdiff::{HexDiffFormat, HexDiffFormatter};
