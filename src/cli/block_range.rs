use std::fmt;
use std::str::FromStr;

use anyhow::{anyhow, Result};

/// Represents a range specification for selecting blocks or runs.
///
/// Supported formats:
/// - `5` - Single item (block/run 5)
/// - `1-10` - Range from 1 to 10 (inclusive)
/// - `5-` - From 5 to end
/// - `3,7,12` - Specific items
/// - `all` - All items
#[derive(Debug, Clone, PartialEq)]
pub enum BlockRange {
    /// A single block number
    Single(usize),
    /// A range from start to end (inclusive)
    Range { start: usize, end: usize },
    /// From start to the end (determined at resolution time)
    FromStart(usize),
    /// Specific block numbers
    List(Vec<usize>),
    /// All blocks
    All,
}

impl BlockRange {
    /// Resolve the range to concrete block numbers given the total count.
    /// Returns an error if any block number is out of bounds.
    pub fn resolve(&self, total: usize) -> Result<Vec<usize>> {
        if total == 0 {
            return Err(anyhow!("No blocks available"));
        }

        let blocks = match self {
            BlockRange::Single(n) => {
                if *n == 0 || *n > total {
                    return Err(anyhow!(
                        "Block {} is out of range (valid: 1-{})",
                        n,
                        total
                    ));
                }
                vec![*n]
            }
            BlockRange::Range { start, end } => {
                if *start == 0 {
                    return Err(anyhow!("Block numbers start at 1"));
                }
                if *start > total {
                    return Err(anyhow!(
                        "Start block {} is out of range (valid: 1-{})",
                        start,
                        total
                    ));
                }
                if *end > total {
                    return Err(anyhow!(
                        "End block {} is out of range (valid: 1-{})",
                        end,
                        total
                    ));
                }
                if *start > *end {
                    return Err(anyhow!(
                        "Invalid range: start ({}) > end ({})",
                        start,
                        end
                    ));
                }
                (*start..=*end).collect()
            }
            BlockRange::FromStart(start) => {
                if *start == 0 {
                    return Err(anyhow!("Block numbers start at 1"));
                }
                if *start > total {
                    return Err(anyhow!(
                        "Start block {} is out of range (valid: 1-{})",
                        start,
                        total
                    ));
                }
                (*start..=total).collect()
            }
            BlockRange::List(items) => {
                for &n in items {
                    if n == 0 || n > total {
                        return Err(anyhow!(
                            "Block {} is out of range (valid: 1-{})",
                            n,
                            total
                        ));
                    }
                }
                items.clone()
            }
            BlockRange::All => (1..=total).collect(),
        };

        Ok(blocks)
    }

    /// Returns true if this is a single-block selection.
    pub fn is_single(&self) -> bool {
        matches!(self, BlockRange::Single(_))
    }

    /// Returns the single block number if this is a single selection.
    pub fn as_single(&self) -> Option<usize> {
        match self {
            BlockRange::Single(n) => Some(*n),
            _ => None,
        }
    }
}

impl FromStr for BlockRange {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let s = s.trim();

        // Handle "all" keyword
        if s.eq_ignore_ascii_case("all") {
            return Ok(BlockRange::All);
        }

        // Handle comma-separated list: "3,7,12"
        if s.contains(',') {
            let items: Result<Vec<usize>, _> = s
                .split(',')
                .map(|part| {
                    part.trim()
                        .parse::<usize>()
                        .map_err(|_| anyhow!("Invalid number in list: '{}'", part.trim()))
                })
                .collect();
            let items = items?;
            if items.is_empty() {
                return Err(anyhow!("Empty block list"));
            }
            return Ok(BlockRange::List(items));
        }

        // Handle range formats: "1-10" or "5-"
        if s.contains('-') {
            let parts: Vec<&str> = s.splitn(2, '-').collect();
            if parts.len() != 2 {
                return Err(anyhow!("Invalid range format: '{}'", s));
            }

            let start_str = parts[0].trim();
            let end_str = parts[1].trim();

            // Parse start (required)
            let start: usize = start_str
                .parse()
                .map_err(|_| anyhow!("Invalid start number: '{}'", start_str))?;

            // End is optional (empty means "to end")
            if end_str.is_empty() {
                return Ok(BlockRange::FromStart(start));
            }

            let end: usize = end_str
                .parse()
                .map_err(|_| anyhow!("Invalid end number: '{}'", end_str))?;

            return Ok(BlockRange::Range { start, end });
        }

        // Single number
        let n: usize = s
            .parse()
            .map_err(|_| anyhow!("Invalid block number: '{}'\n\nExpected formats:\n  5       - single block\n  1-10    - range\n  5-      - from 5 to end\n  3,7,12  - specific blocks\n  all     - all blocks", s))?;

        Ok(BlockRange::Single(n))
    }
}

impl fmt::Display for BlockRange {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BlockRange::Single(n) => write!(f, "{}", n),
            BlockRange::Range { start, end } => write!(f, "{}-{}", start, end),
            BlockRange::FromStart(start) => write!(f, "{}-", start),
            BlockRange::List(items) => {
                let strs: Vec<String> = items.iter().map(|n| n.to_string()).collect();
                write!(f, "{}", strs.join(","))
            }
            BlockRange::All => write!(f, "all"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_single() {
        assert_eq!("5".parse::<BlockRange>().unwrap(), BlockRange::Single(5));
        assert_eq!("1".parse::<BlockRange>().unwrap(), BlockRange::Single(1));
        assert_eq!("100".parse::<BlockRange>().unwrap(), BlockRange::Single(100));
    }

    #[test]
    fn test_parse_range() {
        assert_eq!(
            "1-10".parse::<BlockRange>().unwrap(),
            BlockRange::Range { start: 1, end: 10 }
        );
        assert_eq!(
            "5-20".parse::<BlockRange>().unwrap(),
            BlockRange::Range { start: 5, end: 20 }
        );
    }

    #[test]
    fn test_parse_from_start() {
        assert_eq!(
            "5-".parse::<BlockRange>().unwrap(),
            BlockRange::FromStart(5)
        );
        assert_eq!(
            "1-".parse::<BlockRange>().unwrap(),
            BlockRange::FromStart(1)
        );
    }

    #[test]
    fn test_parse_list() {
        assert_eq!(
            "3,7,12".parse::<BlockRange>().unwrap(),
            BlockRange::List(vec![3, 7, 12])
        );
        assert_eq!(
            "1,2,3".parse::<BlockRange>().unwrap(),
            BlockRange::List(vec![1, 2, 3])
        );
        // With spaces
        assert_eq!(
            "1, 2, 3".parse::<BlockRange>().unwrap(),
            BlockRange::List(vec![1, 2, 3])
        );
    }

    #[test]
    fn test_parse_all() {
        assert_eq!("all".parse::<BlockRange>().unwrap(), BlockRange::All);
        assert_eq!("ALL".parse::<BlockRange>().unwrap(), BlockRange::All);
        assert_eq!("All".parse::<BlockRange>().unwrap(), BlockRange::All);
    }

    #[test]
    fn test_resolve_single() {
        let range = BlockRange::Single(5);
        assert_eq!(range.resolve(10).unwrap(), vec![5]);
        assert!(range.resolve(3).is_err()); // Out of bounds
    }

    #[test]
    fn test_resolve_range() {
        let range = BlockRange::Range { start: 2, end: 5 };
        assert_eq!(range.resolve(10).unwrap(), vec![2, 3, 4, 5]);
        assert!(range.resolve(3).is_err()); // End out of bounds
    }

    #[test]
    fn test_resolve_from_start() {
        let range = BlockRange::FromStart(8);
        assert_eq!(range.resolve(10).unwrap(), vec![8, 9, 10]);
    }

    #[test]
    fn test_resolve_list() {
        let range = BlockRange::List(vec![1, 5, 3]);
        assert_eq!(range.resolve(10).unwrap(), vec![1, 5, 3]);
        assert!(range.resolve(3).is_err()); // 5 out of bounds
    }

    #[test]
    fn test_resolve_all() {
        let range = BlockRange::All;
        assert_eq!(range.resolve(5).unwrap(), vec![1, 2, 3, 4, 5]);
    }

    #[test]
    fn test_display() {
        assert_eq!(BlockRange::Single(5).to_string(), "5");
        assert_eq!(BlockRange::Range { start: 1, end: 10 }.to_string(), "1-10");
        assert_eq!(BlockRange::FromStart(5).to_string(), "5-");
        assert_eq!(BlockRange::List(vec![3, 7, 12]).to_string(), "3,7,12");
        assert_eq!(BlockRange::All.to_string(), "all");
    }

    #[test]
    fn test_is_single() {
        assert!(BlockRange::Single(5).is_single());
        assert!(!BlockRange::All.is_single());
        assert!(!BlockRange::Range { start: 1, end: 5 }.is_single());
    }

    #[test]
    fn test_invalid_formats() {
        assert!("".parse::<BlockRange>().is_err());
        assert!("abc".parse::<BlockRange>().is_err());
        assert!("-5".parse::<BlockRange>().is_err()); // No start
        assert!("1-2-3".parse::<BlockRange>().is_err()); // Parses as 1 to "2-3" which fails
    }

    #[test]
    fn test_zero_block() {
        let range = BlockRange::Single(0);
        assert!(range.resolve(10).is_err());
    }
}
