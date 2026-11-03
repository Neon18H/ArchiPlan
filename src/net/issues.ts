import { cloudText, primaryCloud } from '../catalog/catalog';
import type { AppNode, Issue } from '../types';
import type { NetAnalysis } from './reach';

/** Convierte el análisis de red en problemas para el panel «Problemas» y el lienzo. */
export function netIssues(a: NetAnalysis, nodes: AppNode[]): Issue[] {
  const cloud = primaryCloud(nodes);
  const out: Issue[] = [];
  for (const v of a.verdicts.values()) {
    for (const c of v.checks) {
      if (c.ok) continue;
      out.push({
        id: `net:${v.edgeId}:${c.id}`,
        severity: c.severity,
        title: cloudText(c.title, cloud),
        detail: cloudText(`${c.detail}${c.severity === 'error' && v.failure ? ` Efecto para el usuario: ${v.failure}.` : ''}`, cloud),
        nodeIds: [v.fromId, v.toId],
        edgeIds: [v.edgeId],
        ...(c.fix ? { netFix: c.fix } : {}),
      });
    }
  }
  for (const g of a.general) {
    out.push({ id: `net:${g.id}`, severity: g.severity, title: cloudText(g.title, cloud), detail: cloudText(g.detail, cloud), nodeIds: g.nodeIds ?? [], ...(g.fix ? { netFix: g.fix } : {}) });
  }
  return out;
}
