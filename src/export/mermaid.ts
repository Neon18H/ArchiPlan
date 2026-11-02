import { CATEGORIES, getService } from '../catalog/catalog';
import { isService, isZone } from '../lib/graph';
import type { AppEdge, AppNode, ConnData } from '../types';

const safeId = (id: string) => id.replace(/[^a-zA-Z0-9_]/g, '_');
const esc = (s: string) => s.replace(/"/g, '#quot;').replace(/[<>]/g, '');

/** Diagrama como código en Mermaid (flowchart con subgraphs por zona). */
export function toMermaid(nodes: AppNode[], edges: AppEdge[], title = ''): string {
  const lines: string[] = [];
  if (title) lines.push('---', `title: ${title.replace(/:/g, ' -')}`, '---');
  lines.push('flowchart LR');
  const children = new Map<string | undefined, AppNode[]>();
  for (const n of nodes) {
    const k = n.parentId;
    if (!children.has(k)) children.set(k, []);
    children.get(k)!.push(n);
  }
  const usedCats = new Set<string>();
  const emit = (parent: string | undefined, indent: string) => {
    for (const n of children.get(parent) ?? []) {
      if (isZone(n)) {
        lines.push(`${indent}subgraph ${safeId(n.id)}["${esc(n.data.label)}"]`);
        emit(n.id, indent + '  ');
        lines.push(`${indent}end`);
      } else if (isService(n)) {
        const def = getService(n.data.serviceId);
        usedCats.add(def.category);
        const sub = def.name !== n.data.label ? `<br/><small>${esc(def.name)}</small>` : '';
        const shape = def.role === 'actor' ? ['(["', '"])'] : ['datastore', 'cache', 'search'].includes(def.role) ? ['[("', '")]'] : ['queue', 'topic', 'eventbus', 'stream'].includes(def.role) ? ['[/"', '"/]'] : ['["', '"]'];
        lines.push(`${indent}${safeId(n.id)}${shape[0]}${esc(n.data.label)}${sub}${shape[1]}:::${def.category}`);
      }
    }
  };
  emit(undefined, '  ');
  for (const e of edges) {
    const d = (e.data ?? {}) as ConnData;
    const arrow = d.async ? '-.->' : '-->';
    const label = d.protocol ? `|"${esc(d.protocol)}"|` : '';
    lines.push(`  ${safeId(e.source)} ${arrow}${label} ${safeId(e.target)}`);
  }
  for (const c of usedCats) {
    const col = CATEGORIES[c as keyof typeof CATEGORIES].color;
    lines.push(`  classDef ${c} fill:${col}1a,stroke:${col},color:#1b1f24`);
  }
  for (const n of nodes) {
    if (isZone(n)) lines.push(`  style ${safeId(n.id)} fill:transparent,stroke-dasharray:4 3`);
  }
  return lines.join('\n') + '\n';
}
