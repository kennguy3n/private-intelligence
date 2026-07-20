/**
 * @zk-ai/web — on-device AI inference SDK for the browser.
 *
 * Loads the zk-ai WASM module in a Web Worker (off-main-thread) and
 * exposes a clean async API for summarization, translation, key-point
 * extraction, document generation, slide generation, and image search.
 *
 * Detects WebGPU availability at init time and falls back to WASM SIMD
 * CPU inference if WebGPU is unavailable.
 */

export { ZkAiWeb } from './zk-ai';
export type {
  DeviceProfile,
  TaskResult,
  TaskType,
  ZkAiWebOptions,
} from './types';
