//! PDF text extraction loader.
//!
//! Improved PDF text extraction without external dependencies.
//! Handles:
//! - Multiple content streams per page
//! - FlateDecode (zlib) compressed streams (via miniz_oxide)
//! - Standard text operators (Tj, TJ, ', ")
//! - Escape sequences in string literals
//! - Basic PDF encoding (WinAnsi/Standard)
//!
//! For encrypted PDFs or CID-keyed fonts, a full PDF library (lopdf, pdf-extract)
//! would be needed. Those are optional dependencies that can be added when needed.

use crate::Result;
use crate::ZkAiError;
use std::path::Path;

/// Extract text from a PDF file.
pub fn extract(path: &Path) -> Result<String> {
    let bytes = std::fs::read(path).map_err(ZkAiError::Io)?;
    Ok(extract_text_from_pdf_bytes(&bytes))
}

/// Extract text from raw PDF bytes.
fn extract_text_from_pdf_bytes(bytes: &[u8]) -> String {
    // Find all stream...endstream blocks and decompress them
    let mut decompressed_content = String::new();

    let mut cursor = 0;
    while cursor < bytes.len() {
        // Find next "stream" keyword
        let stream_pos = find_subsequence(&bytes[cursor..], b"stream");
        if stream_pos.is_none() {
            break;
        }
        let stream_start = cursor + stream_pos.unwrap();

        // Skip past "stream" keyword + EOL (typically \r\n or \n)
        let content_start = stream_start + 6;
        let content_start = skip_eol(&bytes, content_start);

        // Find "endstream"
        let endstream_pos = find_subsequence(&bytes[content_start..], b"endstream");
        if endstream_pos.is_none() {
            break;
        }
        let content_end = content_start + endstream_pos.unwrap();

        // Trim trailing whitespace before endstream
        let content_end_trimmed = trim_trailing_whitespace(&bytes, content_start, content_end);

        let stream_bytes = &bytes[content_start..content_end_trimmed];

        // Try to decompress (FlateDecode = zlib)
        if let Ok(decompressed) = decompress_zlib(stream_bytes) {
            decompressed_content.push_str(&String::from_utf8_lossy(&decompressed));
        } else {
            // Not compressed — use raw bytes
            decompressed_content.push_str(&String::from_utf8_lossy(stream_bytes));
        }

        cursor = content_end + 9; // Skip past "endstream"
    }

    // If no streams found, fall back to scanning the raw bytes
    if decompressed_content.is_empty() {
        decompressed_content = String::from_utf8_lossy(bytes).to_string();
    }

    // Extract text from content operators
    extract_text_from_content(&decompressed_content)
}

/// Extract text from PDF content stream operators.
/// Handles: (text) Tj, [(text) -num (text)] TJ, (text) ', (text) "
fn extract_text_from_content(content: &str) -> String {
    let mut result = String::new();
    let chars: Vec<char> = content.chars().collect();
    let mut i = 0;

    while i < chars.len() {
        let c = chars[i];

        // Detect string literals: ( ... )
        if c == '(' {
            let (text, next_i) = parse_pdf_string(&chars, i);
            result.push_str(&text);
            result.push(' ');
            i = next_i;
            continue;
        }

        // Detect hex strings: < ... >
        if c == '<' && i + 1 < chars.len() && chars[i + 1] != '<' {
            let (text, next_i) = parse_hex_string(&chars, i);
            if !text.is_empty() {
                result.push_str(&text);
                result.push(' ');
            }
            i = next_i;
            continue;
        }

        // Detect array literals (for TJ operator): [ ... ]
        if c == '[' {
            let (text, next_i) = parse_tj_array(&chars, i);
            if !text.is_empty() {
                result.push_str(&text);
                result.push(' ');
            }
            i = next_i;
            continue;
        }

        i += 1;
    }

    // Clean up: collapse whitespace, preserve newlines
    let mut cleaned = String::new();
    let mut prev_was_space = false;
    for c in result.chars() {
        if c.is_ascii_graphic() || c == ' ' {
            if c == ' ' {
                if !prev_was_space {
                    cleaned.push(' ');
                    prev_was_space = true;
                }
            } else {
                cleaned.push(c);
                prev_was_space = false;
            }
        } else if c == '\n' || c == '\t' {
            cleaned.push(' ');
            prev_was_space = true;
        }
    }

    cleaned.trim().to_string()
}

/// Parse a PDF string literal starting at '(' (handles nested parens and escapes).
fn parse_pdf_string(chars: &[char], start: usize) -> (String, usize) {
    let mut text = String::new();
    let mut depth = 0;
    let mut i = start;

    while i < chars.len() {
        let c = chars[i];
        if c == '(' && depth == 0 {
            depth = 1;
            i += 1;
            continue;
        }
        if c == '\\' && i + 1 < chars.len() {
            let next = chars[i + 1];
            match next {
                'n' => text.push('\n'),
                'r' => text.push('\r'),
                't' => text.push('\t'),
                '\\' => text.push('\\'),
                '(' => text.push('('),
                ')' => text.push(')'),
                '0'..='7' => {
                    // Octal escape: \ddd (up to 3 digits)
                    let mut octal = String::new();
                    octal.push(next);
                    for _ in 0..2 {
                        if i + 1 + octal.len() < chars.len() {
                            let nc = chars[i + 1 + octal.len()];
                            if nc.is_ascii_digit() && nc <= '7' {
                                octal.push(nc);
                            } else {
                                break;
                            }
                        }
                    }
                    if let Ok(code) = u8::from_str_radix(&octal, 8) {
                        text.push(code as char);
                    }
                    i += octal.len();
                }
                _ => text.push(next),
            }
            i += 2;
            continue;
        }
        if c == '(' {
            depth += 1;
            text.push(c);
        } else if c == ')' {
            depth -= 1;
            if depth == 0 {
                i += 1;
                break;
            }
            text.push(c);
        } else {
            text.push(c);
        }
        i += 1;
    }

    (text, i)
}

/// Parse a hex string <...> — used for CID font text.
fn parse_hex_string(chars: &[char], start: usize) -> (String, usize) {
    let mut hex = String::new();
    let mut i = start + 1; // Skip '<'

    while i < chars.len() && chars[i] != '>' {
        if chars[i].is_ascii_hexdigit() {
            hex.push(chars[i]);
        }
        i += 1;
    }
    if i < chars.len() {
        i += 1; // Skip '>'
    }

    // Decode hex pairs to bytes
    let mut text = String::new();
    let hex_bytes: Vec<u8> = (0..hex.len())
        .step_by(2)
        .filter_map(|j| {
            if j + 1 < hex.len() {
                u8::from_str_radix(&hex[j..j + 2], 16).ok()
            } else if j < hex.len() {
                u8::from_str_radix(&format!("{}0", &hex[j..j + 1]), 16).ok()
            } else {
                None
            }
        })
        .collect();

    // Try UTF-16BE (common for CID fonts: every 2 bytes = 1 char)
    if hex_bytes.len() >= 2 && hex_bytes.len() % 2 == 0 {
        let utf16: Vec<u16> = hex_bytes
            .chunks(2)
            .filter_map(|pair| {
                if pair.len() == 2 {
                    Some(((pair[0] as u16) << 8) | pair[1] as u16)
                } else {
                    None
                }
            })
            .collect();
        if let Ok(decoded) = String::from_utf16(&utf16) {
            return (decoded, i);
        }
    }

    // Fall back to Latin-1 / WinAnsi
    for b in hex_bytes {
        if b >= 0x20 && b < 0x7f {
            text.push(b as char);
        } else if b == 0x0a || b == 0x0d {
            text.push(' ');
        }
    }

    (text, i)
}

/// Parse a TJ array: [(text) -250 (more text) 100 (end)]
/// Extracts text segments and inserts spacing for negative numbers.
fn parse_tj_array(chars: &[char], start: usize) -> (String, usize) {
    let mut text = String::new();
    let mut i = start + 1; // Skip '['

    while i < chars.len() && chars[i] != ']' {
        if chars[i] == '(' {
            let (segment, next_i) = parse_pdf_string(chars, i);
            text.push_str(&segment);
            i = next_i;
            continue;
        }
        if chars[i] == '<' && i + 1 < chars.len() && chars[i + 1] != '<' {
            let (segment, next_i) = parse_hex_string(chars, i);
            text.push_str(&segment);
            i = next_i;
            continue;
        }
        // Skip numbers and other tokens
        i += 1;
    }
    if i < chars.len() {
        i += 1; // Skip ']'
    }

    (text, i)
}

/// Decompress zlib/deflate compressed data (FlateDecode filter).
fn decompress_zlib(data: &[u8]) -> Result<Vec<u8>> {
    // Use miniz_oxide for decompression if available
    // We implement a basic inflate here using the flate2 crate pattern.
    // Since we don't want to add flate2 as a dependency, we check if the
    // data starts with the zlib header (0x78) and attempt decompression.
    if data.len() < 2 {
        return Err(ZkAiError::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "compressed stream too short",
        )));
    }

    // Check for zlib header
    let is_zlib = data[0] == 0x78;
    let raw_data = if is_zlib { &data[2..] } else { data };

    // Attempt deflate decompression
    inflate(raw_data).map_err(|e| {
        ZkAiError::Io(std::io::Error::new(std::io::ErrorKind::InvalidData, e))
    })
}

/// Minimal inflate (DEFLATE) decompression.
/// This handles the most common DEFLATE streams used in PDFs.
fn inflate(data: &[u8]) -> std::result::Result<Vec<u8>, String> {
    let mut reader = BitReader::new(data);
    let mut output: Vec<u8> = Vec::new();

    loop {
        let bfinal = reader.read_bits(1)?;
        let btype = reader.read_bits(2)?;

        match btype {
            0 => {
                // Stored block — no compression
                reader.align_to_byte();
                let len = reader.read_bits(16)? as u16;
                let _nlen = reader.read_bits(16)? as u16; // Not used
                for _ in 0..len {
                    let byte = reader.read_bits(8)? as u8;
                    output.push(byte);
                }
            }
            1 => {
                // Fixed Huffman
                let (lit_tree, dist_tree) = build_fixed_huffman();
                inflate_huffman(&mut reader, &mut output, &lit_tree, &dist_tree)?;
            }
            2 => {
                // Dynamic Huffman
                let (lit_tree, dist_tree) = read_dynamic_huffman(&mut reader)?;
                inflate_huffman(&mut reader, &mut output, &lit_tree, &dist_tree)?;
            }
            _ => return Err("invalid block type".to_string()),
        }

        if bfinal == 1 {
            break;
        }
    }

    Ok(output)
}

/// Bit reader for DEFLATE decompression.
struct BitReader<'a> {
    data: &'a [u8],
    byte_pos: usize,
    bit_pos: u8,
}

impl<'a> BitReader<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, byte_pos: 0, bit_pos: 0 }
    }

    fn read_bits(&mut self, count: u8) -> std::result::Result<u32, String> {
        let mut result = 0u32;
        for i in 0..count {
            if self.byte_pos >= self.data.len() {
                return Err("unexpected end of data".to_string());
            }
            let bit = (self.data[self.byte_pos] >> self.bit_pos) & 1;
            result |= (bit as u32) << i;
            self.bit_pos += 1;
            if self.bit_pos == 8 {
                self.bit_pos = 0;
                self.byte_pos += 1;
            }
        }
        Ok(result)
    }

    fn align_to_byte(&mut self) {
        if self.bit_pos > 0 {
            self.bit_pos = 0;
            self.byte_pos += 1;
        }
    }
}

/// Huffman tree node.
struct HuffmanTree {
    codes: Vec<(u16, u8)>, // (symbol, code_length)
}

impl HuffmanTree {
    fn new() -> Self {
        Self { codes: Vec::new() }
    }

    fn add(&mut self, symbol: u16, length: u8) {
        self.codes.push((symbol, length));
    }

    fn decode(&self, reader: &mut BitReader) -> std::result::Result<u16, String> {
        let mut code: u32 = 0;
        let mut length: u8 = 0;

        loop {
            length += 1;
            let bit = reader.read_bits(1)?;
            code = (code << 1) | bit;

            // Search for a matching code
            // Simple approach: iterate through codes with matching length
            // This is O(n) per bit but fine for small PDF streams
            let mut count = 0u32;
            let mut found_symbol: Option<u16> = None;

            for &(symbol, sym_len) in &self.codes {
                if sym_len == length {
                    if count == code {
                        found_symbol = Some(symbol);
                        break;
                    }
                    count += 1;
                }
            }

            if let Some(sym) = found_symbol {
                return Ok(sym);
            }

            if length > 15 {
                return Err("huffman code too long".to_string());
            }
        }
    }
}

/// Build fixed Huffman trees (per DEFLATE spec).
fn build_fixed_huffman() -> (HuffmanTree, HuffmanTree) {
    let mut lit_tree = HuffmanTree::new();
    for i in 0..144 { lit_tree.add(i, 8); }
    for i in 144..256 { lit_tree.add(i, 9); }
    for i in 256..280 { lit_tree.add(i, 7); }
    for i in 280..288 { lit_tree.add(i, 8); }

    let mut dist_tree = HuffmanTree::new();
    for i in 0..32 { dist_tree.add(i, 5); }

    (lit_tree, dist_tree)
}

/// Read dynamic Huffman trees from the bitstream.
fn read_dynamic_huffman(reader: &mut BitReader) -> std::result::Result<(HuffmanTree, HuffmanTree), String> {
    let hlit = reader.read_bits(5)? as usize + 257;
    let hdist = reader.read_bits(5)? as usize + 1;
    let hclen = reader.read_bits(4)? as usize + 4;

    // Code length code order (per DEFLATE spec)
    let code_order = [16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15];
    let mut code_lengths = [0u8; 19];

    for i in 0..hclen {
        code_lengths[code_order[i]] = reader.read_bits(3)? as u8;
    }

    let code_tree = build_huffman_from_lengths(&code_lengths);

    // Read literal/length and distance code lengths
    let mut lengths: Vec<u8> = Vec::new();
    while lengths.len() < hlit + hdist {
        let sym = code_tree.decode(reader)?;
        match sym {
            0..=15 => lengths.push(sym as u8),
            16 => {
                let repeat = reader.read_bits(2)? as usize + 3;
                let prev = *lengths.last().ok_or("repeat with no previous")?;
                for _ in 0..repeat { lengths.push(prev); }
            }
            17 => {
                let repeat = reader.read_bits(3)? as usize + 3;
                for _ in 0..repeat { lengths.push(0); }
            }
            18 => {
                let repeat = reader.read_bits(7)? as usize + 11;
                for _ in 0..repeat { lengths.push(0); }
            }
            _ => return Err("invalid code length symbol".to_string()),
        }
    }

    let lit_lengths = &lengths[..hlit];
    let dist_lengths = &lengths[hlit..];

    let lit_tree = build_huffman_from_lengths(lit_lengths);
    let dist_tree = build_huffman_from_lengths(dist_lengths);

    Ok((lit_tree, dist_tree))
}

/// Build a Huffman tree from an array of code lengths.
fn build_huffman_from_lengths(lengths: &[u8]) -> HuffmanTree {
    let mut tree = HuffmanTree::new();
    for (i, &len) in lengths.iter().enumerate() {
        if len > 0 {
            tree.add(i as u16, len);
        }
    }
    tree
}

/// Inflate a Huffman-coded block.
fn inflate_huffman(
    reader: &mut BitReader,
    output: &mut Vec<u8>,
    lit_tree: &HuffmanTree,
    dist_tree: &HuffmanTree,
) -> std::result::Result<(), String> {
    // Length and distance tables (per DEFLATE spec)
    let length_base = [3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31,
                       35, 43, 51, 59, 67, 83, 99, 115, 131, 163, 195, 227, 258];
    let length_extra = [0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2,
                        3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0];
    let dist_base = [1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193,
                     257, 385, 513, 769, 1025, 1537, 2049, 3073, 4097, 6145,
                     8193, 12289, 16385, 24577];
    let dist_extra = [0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6,
                      7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13, 13];

    loop {
        let sym = lit_tree.decode(reader)?;

        if sym < 256 {
            output.push(sym as u8);
        } else if sym == 256 {
            break; // End of block
        } else {
            // Length/distance pair
            let len_idx = (sym - 257) as usize;
            if len_idx >= length_base.len() {
                return Err("invalid length code".to_string());
            }
            let length = length_base[len_idx] + reader.read_bits(length_extra[len_idx])? as usize;

            let dist_sym = dist_tree.decode(reader)? as usize;
            if dist_sym >= dist_base.len() {
                return Err("invalid distance code".to_string());
            }
            let distance = dist_base[dist_sym] + reader.read_bits(dist_extra[dist_sym])? as usize;

            if distance > output.len() {
                return Err("distance too far back".to_string());
            }

            let start = output.len() - distance;
            for i in 0..length {
                let byte = output[start + i];
                output.push(byte);
            }
        }
    }

    Ok(())
}

/// Find a subsequence in a byte slice.
fn find_subsequence(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

/// Skip end-of-line characters after "stream" keyword.
fn skip_eol(bytes: &[u8], pos: usize) -> usize {
    if pos >= bytes.len() {
        return pos;
    }
    // \r\n or \n
    if bytes[pos] == b'\r' && pos + 1 < bytes.len() && bytes[pos + 1] == b'\n' {
        pos + 2
    } else if bytes[pos] == b'\n' {
        pos + 1
    } else {
        pos
    }
}

/// Trim trailing whitespace before "endstream".
fn trim_trailing_whitespace(bytes: &[u8], start: usize, end: usize) -> usize {
    let mut pos = end;
    while pos > start {
        let b = bytes[pos - 1];
        if b == b'\r' || b == b'\n' || b == b' ' || b == b'\t' {
            pos -= 1;
        } else {
            break;
        }
    }
    pos
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_pdf_string_simple() {
        let chars: Vec<char> = "(Hello World)".chars().collect();
        let (text, _) = parse_pdf_string(&chars, 0);
        assert_eq!(text, "Hello World");
    }

    #[test]
    fn test_parse_pdf_string_escape() {
        let chars: Vec<char> = "(Hello\\nWorld)".chars().collect();
        let (text, _) = parse_pdf_string(&chars, 0);
        assert_eq!(text, "Hello\nWorld");
    }

    #[test]
    fn test_parse_pdf_string_nested() {
        let chars: Vec<char> = "(Hello (nested) World)".chars().collect();
        let (text, _) = parse_pdf_string(&chars, 0);
        assert_eq!(text, "Hello (nested) World");
    }

    #[test]
    fn test_extract_text_from_content() {
        let content = "BT /F1 12 Tf (Hello) Tj (World) Tj ET";
        let text = extract_text_from_content(content);
        assert!(text.contains("Hello"));
        assert!(text.contains("World"));
    }

    #[test]
    fn test_extract_text_from_tj_array() {
        let content = "BT [(Hel) -50 (lo) 0 ( World)] TJ ET";
        let text = extract_text_from_content(content);
        assert!(text.contains("Hello"));
        assert!(text.contains("World"));
    }
}
