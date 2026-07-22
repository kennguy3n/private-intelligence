//! Plain text file loader.

use crate::Result;
use std::path::Path;

/// Extract text from a plain text or markdown file.
pub fn extract(path: &Path) -> Result<String> {
    std::fs::read_to_string(path).map_err(crate::ZkAiError::Io)
}
