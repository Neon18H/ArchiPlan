import { counterpart, defaultProps, getService, lidOf, zoneLabel } from '../catalog/catalog';
import { REGION_MAP } from '../catalog/azure';
import type { Cloud, PropValue, ZoneKind } from '../types';
import type { Spec } from './layout';

const RESET_TEXT_PROPS = ['instanceType', 'instanceClass', 'nodeType', 'sku', 'version'];

/** Convierte una pieza a su equivalente en otra nube conservando lo que se pueda. */
export function convertService(serviceId: string, props: Record<string, PropValue>, label: string, to: Cloud): { serviceId: string; props: Record<string, PropValue>; label: string } | null {
  const def = getService(serviceId);
  if (def.provider === 'generic' || def.provider === to) return { serviceId, props, label };
  let target = counterpart(serviceId, to);
  if (!target) return null;
  if (to === 'azure' && lidOf(serviceId) === 'rds' && String(props.engine ?? '').startsWith('sqlserver')) target = 'az-sql';
  const tDef = getService(target);
  const defaults = defaultProps(tDef.props);
  const out: Record<string, PropValue> = { ...defaults };
  for (const [k, v] of Object.entries(props)) {
    if (k.startsWith('sim.')) out[k] = v;
    else if (k in defaults && typeof defaults[k] === typeof v && !RESET_TEXT_PROPS.includes(k) && k !== 'engine') out[k] = v;
  }
  for (const pd of tDef.props ?? []) {
    if (pd.type === 'select' && !pd.options.includes(String(out[pd.key]))) out[pd.key] = pd.default;
  }
  if (to === 'aws' && target === 'rds') out.engine = serviceId === 'az-sql' ? 'sqlserver-ex' : String(props.engine) === 'mysql' ? 'mysql' : 'postgres';
  if (to === 'azure' && target === 'az-postgres' && String(props.engine ?? '').includes('mysql')) out.engine = 'mysql';
  return { serviceId: target, props: out, label: label === def.name ? tDef.name : label };
}

export function convertRegion(region: string, to: Cloud): string {
  if (to === 'azure') return REGION_MAP[region] ?? (Object.values(REGION_MAP).includes(region) ? region : 'eastus');
  const back = Object.entries(REGION_MAP).find(([, v]) => v === region)?.[0];
  return back ?? (region.includes('-') ? region : 'us-east-1');
}

export function convertZoneLabel(kind: ZoneKind, label: string, to: Cloud): string {
  const from: Cloud = to === 'azure' ? 'aws' : 'azure';
  return label === zoneLabel(kind, from) ? zoneLabel(kind, to) : label;
}

/** Convierte una especificación (plantilla / asistente) a otra nube. */
export function convertSpec(spec: Spec, to: Cloud): Spec {
  if (to === 'aws') return { ...spec, cloud: 'aws' };
  const services = spec.services.flatMap((s) => {
    const c = convertService(s.serviceId, { ...defaultProps(getService(s.serviceId).props), ...(s.props ?? {}) }, s.label ?? getService(s.serviceId).name, to);
    return c ? [{ ...s, serviceId: c.serviceId, props: c.props, label: c.label }] : [];
  });
  const keys = new Set(services.map((s) => s.key));
  return { ...spec, cloud: to, region: convertRegion(spec.region ?? 'us-east-1', to), services, edges: spec.edges.filter(([a, b]) => keys.has(a) && keys.has(b)) };
}
