import { createContext, useContext } from 'react';
import type { NodeFrame } from '../sim/engine';
import type { Severity } from '../types';

export interface CanvasCtx {
  nodeIssues: Map<string, Severity>;
  edgeIssues: Map<string, Severity>;
  dimmed: Set<string>;
  readOnly: boolean;
  sim: { nodes: Record<string, NodeFrame>; edges: Record<string, { rps: number; attack: number }>; targetId: string | null; playing: boolean } | null;
}

export const CanvasContext = createContext<CanvasCtx>({ nodeIssues: new Map(), edgeIssues: new Map(), dimmed: new Set(), readOnly: false, sim: null });
export const useCanvasCtx = () => useContext(CanvasContext);
