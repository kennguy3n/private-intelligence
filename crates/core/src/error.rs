use thiserror::Error;

/// Errors returned by zk-ai-core.
#[derive(Error, Debug)]
pub enum ZkAiError {
    #[error("device profiling failed: {0}")]
    Profiler(String),

    #[error("model not found: {0}")]
    ModelNotFound(String),

    #[error("model download failed: {0}")]
    ModelDownload(String),

    #[error("model integrity check failed: expected {expected}, got {actual}")]
    ModelIntegrity { expected: String, actual: String },

    #[error("model load failed: {0}")]
    ModelLoad(String),

    #[error("inference failed: {0}")]
    Inference(String),

    #[error("tokenizer error: {0}")]
    Tokenizer(String),

    #[error("LoRA adapter error: {0}")]
    LoRA(String),

    #[error("resource limit exceeded: {0}")]
    ResourceLimit(String),

    #[error("inference timeout after {0:?}")]
    Timeout(std::time::Duration),

    #[error("cache error: {0}")]
    Cache(String),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("serialization error: {0}")]
    Serialization(String),

    #[error("unsupported task: {0}")]
    UnsupportedTask(String),

    #[error("unsupported language: {0}")]
    UnsupportedLanguage(String),

    #[error("strict ZK: server offload not available for strict_zk content")]
    StrictZkForbidden,

    #[error("swarm inference error: {0}")]
    Swarm(String),

    #[error("backend error: {0}")]
    Backend(String),
}

impl From<serde_json::Error> for ZkAiError {
    fn from(e: serde_json::Error) -> Self {
        ZkAiError::Serialization(e.to_string())
    }
}

impl From<toml::de::Error> for ZkAiError {
    fn from(e: toml::de::Error) -> Self {
        ZkAiError::Serialization(e.to_string())
    }
}

pub type Result<T> = std::result::Result<T, ZkAiError>;
