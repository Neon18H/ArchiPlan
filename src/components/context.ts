import { createContext, useContext } from 'react';
import type { Severity } from '../types';

export interface CanvasCtx {
  nodeIssues: Map<string, Severity>;
  edgeIssues: Map<string, Severity>;
  dimmed: Set<string>;
  readOnly: boolean;
}

export const CanvasContext = createContext<CanvasCtx>({ nodeIssues: new Map(), edgeIssues: new Map(), dimmed: new Set(), readOnly: false });
export const useCanvasCtx = () => useContext(CanvasContext);
