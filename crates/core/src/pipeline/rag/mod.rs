//! RAG (Retrieval-Augmented Generation) module.
//!
//! Provides document chunking, indexing, retrieval, and answer generation
//! for enterprise document Q&A. Uses e5-small for embeddings and mT5-small
//! for answer synthesis.

pub mod chunker;
pub mod index;
pub mod retrieval;
pub mod generation;
