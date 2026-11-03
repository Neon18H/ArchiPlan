import { createContext, useContext } from 'react';
import type { NodeFrame } from '../sim/engine';
import type { HopStatus } from '../net/trace';
import type { Cloud, Severity } from '../types';

export interface CanvasCtx {
  nodeIssues: Map<string, Severity>;
  edgeIssues: Map<string, Severity>;
  dimmed: Set<string>;
  readOnly: boolean;
  cloud: Cloud;
  stride: { nodes: Map<string, { open: number; worst: string | null }>; boundaries: Map<string, string> } | null;
  sim: { nodes: Record<string, NodeFrame>; edges: Record<string, { rps: number; attack: number }>; targetId: string | null; playing: boolean } | null;
  /** Trazado de una petición de usuario (modo «Petición de usuario»). */
  trace?: { nodes: Map<string, HopStatus>; edges: Map<string, HopStatus>; failedEdgeId: string | null; current: string | null } | null;
  /** Flechas que la configuración de red bloquea (id → etiqueta corta). */
  netBlocked?: Map<string, string>;
}

export const CanvasContext = createContext<CanvasCtx>({ nodeIssues: new Map(), edgeIssues: new Map(), dimmed: new Set(), readOnly: false, sim: null, stride: null, cloud: 'aws' });
export const useCanvasCtx = () => useContext(CanvasContext);
