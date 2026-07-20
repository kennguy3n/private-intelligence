/**
 * ZkAiWeb — the main entry point for browser-based AI inference.
 *
 * Loads the zk-ai WASM module in a Web Worker to keep inference
 * off the main thread. Detects WebGPU support and configures the
 * engine accordingly.
 */

import type { DeviceProfile, TaskResult, ZkAiWebOptions } from './types';

export class ZkAiWeb {
  private worker: Worker | null = null;
  private profile: DeviceProfile | null = null;
  private initialized = false;

  /**
   * Initialize the AI engine. Must be called before any task method.
   *
   * This creates a Web Worker, loads the WASM module, detects device
   * capabilities (WebGPU, CPU cores, memory), and prepares the model
   * cache.
   */
  async init(options: ZkAiWebOptions = {}): Promise<void> {
    if (this.initialized) return;

    const hasWebGPU = !options.forceCpu && 'gpu' in navigator;
    const cpuCores = navigator.hardwareConcurrency || 4;
    // @ts-ignore — deviceMemory is not in all TS lib versions
    const deviceMemoryMb = ((navigator.deviceMemory || 4) as number) * 1024;
    const batteryLevel = await this.getBatteryLevel();

    // Create the Web Worker
    const workerUrl = options.wasmUrl
      ? options.wasmUrl
      : new URL('./zk-ai-worker.js', import.meta.url).href;

    this.worker = new Worker(workerUrl, { type: 'module' });

    // Wait for the worker to be ready
    await this.postMessage('init', {
      hasWebGPU,
      cpuCores,
      deviceMemoryMb,
      batteryLevel,
      cacheDir: options.cacheDir || 'zk-ai-cache',
    });

    // Get device profile
    const profileResult = await this.postMessage('profile', {});
    this.profile = profileResult as DeviceProfile;
    this.initialized = true;
  }

  /** Get the detected device profile. */
  getProfile(): DeviceProfile | null {
    return this.profile;
  }

  /** Summarize text in the given language. */
  async summarize(text: string, language: string = 'en'): Promise<TaskResult> {
    return this.postMessage('summarize', { text, language }) as Promise<TaskResult>;
  }

  /** Extract key points from text. */
  async keyPoints(text: string, language: string = 'en'): Promise<TaskResult> {
    return this.postMessage('key_points', { text, language }) as Promise<TaskResult>;
  }

  /** Translate text between languages. */
  async translate(text: string, sourceLang: string, targetLang: string): Promise<TaskResult> {
    return this.postMessage('translate', { text, sourceLang, targetLang }) as Promise<TaskResult>;
  }

  /** Generate a document from a topic and outline. */
  async generateDoc(topic: string, outline: string, language: string = 'en'): Promise<TaskResult> {
    return this.postMessage('generate_doc', { topic, outline, language }) as Promise<TaskResult>;
  }

  /** Generate slide content from a topic and source content. */
  async generateSlides(topic: string, sourceContent: string, language: string = 'en'): Promise<TaskResult> {
    return this.postMessage('generate_slides', { topic, sourceContent, language }) as Promise<TaskResult>;
  }

  /** Search for images matching a query (requires CLIP model). */
  async imageSearch(query: string): Promise<TaskResult> {
    return this.postMessage('image_search', { query }) as Promise<TaskResult>;
  }

  /** Shutdown the engine and terminate the worker. */
  async shutdown(): Promise<void> {
    if (this.worker) {
      await this.postMessage('shutdown', {});
      this.worker.terminate();
      this.worker = null;
    }
    this.initialized = false;
  }

  // ─── Internal helpers ──────────────────────────────────────────

  private postMessage(method: string, args: Record<string, unknown>): Promise<unknown> {
    return new Promise((resolve, reject) => {
      if (!this.worker) {
        reject(new Error('ZkAiWeb not initialized. Call init() first.'));
        return;
      }

      const id = crypto.randomUUID();
      const timeoutMs = 30000;
      let settled = false;

      const handler = (event: MessageEvent) => {
        const data = event.data;
        if (data.id === id) {
          if (settled) return;
          settled = true;
          clearTimeout(timer);
          this.worker!.removeEventListener('message', handler);
          if (data.error) {
            reject(new Error(data.error));
          } else {
            resolve(data.result);
          }
        }
      };

      const timer = setTimeout(() => {
        if (settled) return;
        settled = true;
        this.worker!.removeEventListener('message', handler);
        reject(new Error(`Worker timeout after ${timeoutMs}ms for method: ${method}`));
      }, timeoutMs);

      this.worker.addEventListener('message', handler);
      this.worker.postMessage({ id, method, ...args });
    });
  }

  private async getBatteryLevel(): Promise<number | undefined> {
    try {
      // @ts-ignore — Battery API not in all TS lib versions
      const battery = await navigator.getBattery?.();
      return battery ? Math.round(battery.level * 100) : undefined;
    } catch {
      return undefined;
    }
  }
}
