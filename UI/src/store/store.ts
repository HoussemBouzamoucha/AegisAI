// File: UI/src/store.ts
// Zustand store — provides state and actions to Scanner.tsx and other components

import { create } from 'zustand';
import { invoke } from '@tauri-apps/api/core';
import type { ScanResult, ScanStats, ScanOutput } from '../types/types';

interface StoreState {
  // ── State ────────────────────────────────────────────────
  scanning: boolean;
  scanResults: ScanResult[];
  scanStats: ScanStats | null;
  scanError: string | null;

  // ── Actions ──────────────────────────────────────────────
  scanFile: (path: string) => Promise<void>;
  scanDirectory: (path: string) => Promise<void>;
  clearScan: () => void;
}

export const useStore = create<StoreState>((set) => ({
  // ── Initial state ─────────────────────────────────────────
  scanning:    false,
  scanResults: [],
  scanStats:   null,
  scanError:   null,

  // ── Scan a single file ────────────────────────────────────
  scanFile: async (path: string) => {
    set({ scanning: true, scanError: null, scanResults: [], scanStats: null });
    console.log('scanFile called with:', path); // ADD

    try {
      const output = await invoke<ScanOutput>('scan_file', { path });
      console.log('RAW OUTPUT:', JSON.stringify(output)); // ADD

      if (!output.success && output.error) {
        set({ scanError: output.error, scanning: false });
        return;
      }

      set({ scanResults: output.files, scanStats: output.statistics, scanning: false });
      console.log('scanResults set to:', JSON.stringify(output.files)); // ADD

    } catch (err: unknown) {
      console.error('INVOKE ERROR:', err); // ADD
      set({
        scanError: err instanceof Error ? err.message : String(err),
        scanning: false,
      });
    }
  },

  // ── Scan a directory ──────────────────────────────────────
  scanDirectory: async (path: string) => {
    set({ scanning: true, scanError: null, scanResults: [], scanStats: null });

    try {
      const output = await invoke<ScanOutput>('scan_directory', { path });

      if (!output.success && output.error) {
        set({ scanError: output.error, scanning: false });
        return;
      }

      set({ scanResults: output.files, scanStats: output.statistics, scanning: false });

    } catch (err: unknown) {
      set({
        scanError: err instanceof Error ? err.message : String(err),
        scanning: false,
      });
    }
  },

  // ── Clear results ─────────────────────────────────────────
  clearScan: () => set({
    scanResults: [],
    scanStats:   null,
    scanError:   null,
    scanning:    false,
  }),
}));