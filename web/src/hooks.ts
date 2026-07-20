/**
 * React hooks for @zk-ai/web.
 *
 * Provides convenient hooks for using zk-ai in React applications.
 * Each hook manages the engine lifecycle and exposes loading/error state.
 * All task hooks share a single ZkAiWeb instance via getSharedEngine().
 */

import { useState, useEffect, useCallback, useRef } from 'react';
import { ZkAiWeb } from './zk-ai';
import type { DeviceProfile, TaskResult, ZkAiWebOptions } from './types';

// Shared singleton engine — all hooks reuse the same Web Worker + WASM instance.
let sharedEngine: ZkAiWeb | null = null;
let sharedPromise: Promise<ZkAiWeb> | null = null;
let sharedOptions: ZkAiWebOptions | null = null;

function getSharedEngine(options?: ZkAiWebOptions): Promise<ZkAiWeb> {
  if (sharedEngine) return Promise.resolve(sharedEngine);
  if (sharedPromise) return sharedPromise;

  const ai = new ZkAiWeb();
  sharedOptions = options || null;
  sharedPromise = ai.init(options || {}).then(() => {
    sharedEngine = ai;
    return ai;
  });
  return sharedPromise;
}

/**
 * Initialize a ZkAiWeb instance. Returns the engine, profile, and status.
 *
 * @example
 * const { engine, profile, loading, error } = useZkAi();
 * if (loading) return <Spinner />;
 * const result = await engine.summarize(text, 'vi');
 */
export function useZkAi(options?: ZkAiWebOptions) {
  const [engine, setEngine] = useState<ZkAiWeb | null>(null);
  const [profile, setProfile] = useState<DeviceProfile | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const optionsRef = useRef(options);
  optionsRef.current = options;

  useEffect(() => {
    let cancelled = false;

    getSharedEngine(optionsRef.current || undefined)
      .then((ai) => {
        if (cancelled) return;
        setProfile(ai.getProfile());
        setEngine(ai);
        setLoading(false);
      })
      .catch((err) => {
        if (cancelled) return;
        setError(err.message);
        setLoading(false);
      });

    return () => {
      cancelled = true;
    };
  }, []);

  return { engine, profile, loading, error };
}

/**
 * Summarize text with loading state.
 *
 * @example
 * const { summarize, result, loading, error } = useSummarize();
 * <button onClick={() => summarize(documentText, 'vi')}>Summarize</button>
 */
export function useSummarize() {
  const [result, setResult] = useState<TaskResult | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const engineRef = useRef<ZkAiWeb | null>(null);

  useEffect(() => {
    let cancelled = false;
    getSharedEngine().then((ai) => {
      if (!cancelled) engineRef.current = ai;
    }).catch((err) => setError(err.message));
    return () => { cancelled = true; };
  }, []);

  const summarize = useCallback(async (text: string, language: string = 'en') => {
    if (!engineRef.current) {
      setError('Engine not initialized');
      return;
    }
    setLoading(true);
    setError(null);
    try {
      const r = await engineRef.current.summarize(text, language);
      setResult(r);
    } catch (err: any) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  }, []);

  return { summarize, result, loading, error };
}

/**
 * Translate text with loading state.
 */
export function useTranslate() {
  const [result, setResult] = useState<TaskResult | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const engineRef = useRef<ZkAiWeb | null>(null);

  useEffect(() => {
    let cancelled = false;
    getSharedEngine().then((ai) => {
      if (!cancelled) engineRef.current = ai;
    }).catch((err) => setError(err.message));
    return () => { cancelled = true; };
  }, []);

  const translate = useCallback(async (text: string, sourceLang: string, targetLang: string) => {
    if (!engineRef.current) { setError('Engine not initialized'); return; }
    setLoading(true); setError(null);
    try {
      const r = await engineRef.current.translate(text, sourceLang, targetLang);
      setResult(r);
    } catch (err: any) { setError(err.message); }
    finally { setLoading(false); }
  }, []);

  return { translate, result, loading, error };
}

/**
 * Extract key points with loading state.
 */
export function useKeyPoints() {
  const [result, setResult] = useState<TaskResult | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const engineRef = useRef<ZkAiWeb | null>(null);

  useEffect(() => {
    let cancelled = false;
    getSharedEngine().then((ai) => {
      if (!cancelled) engineRef.current = ai;
    }).catch((err) => setError(err.message));
    return () => { cancelled = true; };
  }, []);

  const keyPoints = useCallback(async (text: string, language: string = 'en') => {
    if (!engineRef.current) { setError('Engine not initialized'); return; }
    setLoading(true); setError(null);
    try {
      const r = await engineRef.current.keyPoints(text, language);
      setResult(r);
    } catch (err: any) { setError(err.message); }
    finally { setLoading(false); }
  }, []);

  return { keyPoints, result, loading, error };
}

/**
 * Generate a document with loading state.
 */
export function useGenerateDoc() {
  const [result, setResult] = useState<TaskResult | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const engineRef = useRef<ZkAiWeb | null>(null);

  useEffect(() => {
    let cancelled = false;
    getSharedEngine().then((ai) => {
      if (!cancelled) engineRef.current = ai;
    }).catch((err) => setError(err.message));
    return () => { cancelled = true; };
  }, []);

  const generateDoc = useCallback(async (topic: string, outline: string, language: string = 'en') => {
    if (!engineRef.current) { setError('Engine not initialized'); return; }
    setLoading(true); setError(null);
    try {
      const r = await engineRef.current.generateDoc(topic, outline, language);
      setResult(r);
    } catch (err: any) { setError(err.message); }
    finally { setLoading(false); }
  }, []);

  return { generateDoc, result, loading, error };
}

/**
 * Generate slide content with loading state.
 */
export function useGenerateSlides() {
  const [result, setResult] = useState<TaskResult | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const engineRef = useRef<ZkAiWeb | null>(null);

  useEffect(() => {
    let cancelled = false;
    getSharedEngine().then((ai) => {
      if (!cancelled) engineRef.current = ai;
    }).catch((err) => setError(err.message));
    return () => { cancelled = true; };
  }, []);

  const generateSlides = useCallback(async (topic: string, sourceContent: string, language: string = 'en') => {
    if (!engineRef.current) { setError('Engine not initialized'); return; }
    setLoading(true); setError(null);
    try {
      const r = await engineRef.current.generateSlides(topic, sourceContent, language);
      setResult(r);
    } catch (err: any) { setError(err.message); }
    finally { setLoading(false); }
  }, []);

  return { generateSlides, result, loading, error };
}

/**
 * Search for images with loading state.
 */
export function useImageSearch() {
  const [result, setResult] = useState<TaskResult | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const engineRef = useRef<ZkAiWeb | null>(null);

  useEffect(() => {
    let cancelled = false;
    getSharedEngine().then((ai) => {
      if (!cancelled) engineRef.current = ai;
    }).catch((err) => setError(err.message));
    return () => { cancelled = true; };
  }, []);

  const imageSearch = useCallback(async (query: string) => {
    if (!engineRef.current) { setError('Engine not initialized'); return; }
    setLoading(true); setError(null);
    try {
      const r = await engineRef.current.imageSearch(query);
      setResult(r);
    } catch (err: any) { setError(err.message); }
    finally { setLoading(false); }
  }, []);

  return { imageSearch, result, loading, error };
}
