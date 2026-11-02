import type { Project } from '../types';

export interface ProjectListItem {
  id: string;
  name: string;
  updatedAt: string;
  nodes: number;
}

export async function serverAvailable(): Promise<boolean> {
  try {
    const r = await fetch('/api/health');
    return r.ok;
  } catch {
    return false;
  }
}

export async function listProjects(): Promise<ProjectListItem[]> {
  const r = await fetch('/api/projects');
  if (!r.ok) throw new Error('No se pudo listar los proyectos');
  return r.json();
}

export async function loadProjectFile(id: string): Promise<Project> {
  const r = await fetch(`/api/projects/${encodeURIComponent(id)}`);
  if (!r.ok) throw new Error('No se pudo abrir el proyecto');
  return r.json();
}

export async function saveProjectFile(id: string, p: Project): Promise<void> {
  const r = await fetch(`/api/projects/${encodeURIComponent(id)}`, {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(p, null, 2),
  });
  if (!r.ok) throw new Error((await r.json().catch(() => ({})))?.error || 'No se pudo guardar');
}

export async function deleteProjectFile(id: string): Promise<void> {
  await fetch(`/api/projects/${encodeURIComponent(id)}`, { method: 'DELETE' });
}

export function slugify(s: string) {
  return (
    s
      .normalize('NFD')
      .replace(/[̀-ͯ]/g, '')
      .toLowerCase()
      .replace(/[^a-z0-9]+/g, '-')
      .replace(/^-|-$/g, '')
      .slice(0, 60) || 'arquitectura'
  );
}

export function isProject(x: unknown): x is Project {
  const p = x as Project;
  return !!p && p.format === 'archiplan' && Array.isArray(p.nodes) && Array.isArray(p.edges);
}
