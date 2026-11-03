import { cloudText, primaryCloud } from '../catalog/catalog';
import { useStore } from '../store';
import type { Cloud } from '../types';

/** Nube principal del diagrama (reactiva). */
export function useCloud(): Cloud {
  return useStore((s) => primaryCloud(s.nodes, s.meta.provider ?? 'aws'));
}

/** Traductor de textos de reglas a la nube del diagrama. */
export function useCloudText(): (t: string) => string {
  const cloud = useCloud();
  return (t: string) => cloudText(t, cloud);
}
