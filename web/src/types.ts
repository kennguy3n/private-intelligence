/**
 * Type definitions for @zk-ai/web.
 */

export interface DeviceProfile {
  tier: 'high_end' | 'mid_range' | 'low_end' | 'throttled';
  acceleration: 'metal' | 'coreml' | 'directml' | 'cuda' | 'vulkan' | 'nnapi' | 'webgpu' | 'cpu_simd' | 'cpu';
  memoryMb: number;
  cpuCores: number;
  hasNpu: boolean;
  platform: string;
}

export type TaskType =
  | 'summarize'
  | 'translate'
  | 'key_points'
  | 'generate_doc'
  | 'generate_slides'
  | 'image_search';

export interface TaskResult {
  output: string;
  task: TaskType;
  model: string;
  adapter: string | null;
  durationMs: number;
}

export interface ZkAiWebOptions {
  /** Directory name for the model cache (uses OPFS or Cache API). */
  cacheDir?: string;
  /** URL to the WASM file (defaults to same origin). */
  wasmUrl?: string;
  /** Whether to force CPU-only mode (skip WebGPU detection). */
  forceCpu?: boolean;
}
