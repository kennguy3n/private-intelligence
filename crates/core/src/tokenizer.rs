//! Tokenizer wrapper around the HuggingFace `tokenizers` crate.
//!
//! Loads a tokenizer from a `tokenizer.json` file (the standard
//! HuggingFace fast tokenizer format) and provides encode/decode
//! operations for the inference pipeline.

use std::path::Path;
use tokenizers::Tokenizer;
use crate::{Result, ZkAiError};

/// A loaded tokenizer ready for encode/decode operations.
pub struct AiTokenizer {
    inner: Tokenizer,
}

/// Encoded input ready to be fed into an ONNX model.
pub struct EncodedInput {
    /// Token IDs (input_ids).
    pub input_ids: Vec<u32>,
    /// Attention mask (1 for real tokens, 0 for padding).
    pub attention_mask: Vec<u32>,
    /// Token type IDs (segment IDs, typically all zeros for single-sentence).
    pub token_type_ids: Vec<u32>,
    /// Number of non-padding tokens.
    pub actual_len: usize,
}

impl AiTokenizer {
    /// Load a tokenizer from a `tokenizer.json` file on disk.
    pub fn from_file(path: &Path) -> Result<Self> {
        if !path.exists() {
            return Err(ZkAiError::Tokenizer(format!(
                "tokenizer file not found: {:?}",
                path
            )));
        }
        let tokenizer = Tokenizer::from_file(path)
            .map_err(|e| ZkAiError::Tokenizer(format!("failed to load tokenizer: {e}")))?;
        Ok(Self { inner: tokenizer })
    }

    /// Create a tokenizer from an in-memory JSON string.
    pub fn from_json(json: &str) -> Result<Self> {
        let tokenizer = Tokenizer::from_bytes(json.as_bytes())
            .map_err(|e| ZkAiError::Tokenizer(format!("failed to parse tokenizer JSON: {e}")))?;
        Ok(Self { inner: tokenizer })
    }

    /// Encode a text string into token IDs for model input.
    ///
    /// `max_length` caps the sequence length (0 = use tokenizer default).
    pub fn encode(&self, text: &str, max_length: usize) -> Result<EncodedInput> {
        let mut encoding = self
            .inner
            .encode(text, true)
            .map_err(|e| ZkAiError::Tokenizer(format!("encode failed: {e}")))?;

        // Truncate if needed
        if max_length > 0 && encoding.len() > max_length {
            encoding.truncate(max_length, 0, tokenizers::TruncationDirection::Right);
        }

        let input_ids: Vec<u32> = encoding.get_ids().iter().map(|&v| v).collect();
        let attention_mask: Vec<u32> = encoding.get_attention_mask().iter().map(|&v| v).collect();
        let token_type_ids: Vec<u32> = encoding.get_type_ids().iter().map(|&v| v).collect();
        let actual_len = attention_mask.iter().filter(|&&m| m == 1).count();

        Ok(EncodedInput {
            input_ids,
            attention_mask,
            token_type_ids,
            actual_len,
        })
    }

    /// Decode a sequence of token IDs back into text.
    pub fn decode(&self, token_ids: &[u32], skip_special_tokens: bool) -> Result<String> {
        self.inner
            .decode(token_ids, skip_special_tokens)
            .map_err(|e| ZkAiError::Tokenizer(format!("decode failed: {e}")))
    }

    /// Get the vocabulary size.
    pub fn vocab_size(&self) -> usize {
        self.inner.get_vocab_size(true)
    }

    /// Get the padding token ID (if any).
    pub fn pad_token_id(&self) -> Option<u32> {
        self.inner.get_padding().map(|p| p.pad_id)
    }

    /// Get the model's max sequence length (from tokenizer config).
    pub fn model_max_length(&self) -> usize {
        self.inner
            .get_truncation()
            .map(|t| t.max_length)
            .unwrap_or(512)
    }
}

impl std::fmt::Debug for AiTokenizer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AiTokenizer")
            .field("vocab_size", &self.vocab_size())
            .field("model_max_length", &self.model_max_length())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encoded_input_fields() {
        // Verify the struct layout is what we expect
        let encoded = EncodedInput {
            input_ids: vec![1, 2, 3, 0, 0],
            attention_mask: vec![1, 1, 1, 0, 0],
            token_type_ids: vec![0, 0, 0, 0, 0],
            actual_len: 3,
        };
        assert_eq!(encoded.input_ids.len(), 5);
        assert_eq!(encoded.actual_len, 3);
    }
}
