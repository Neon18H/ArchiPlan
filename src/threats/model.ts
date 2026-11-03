/**
 * Modelo de amenazas STRIDE generado a partir del diagrama.
 *
 * - Cada pieza se ubica en una ZONA DE CONFIANZA según dónde está dibujada.
 * - Una flecha que pasa de una zona a otra de mayor confianza cruza un LÍMITE DE CONFIANZA.
 * - Las reglas generan amenazas por elemento (actores, puntos de entrada, cómputo, datos,
 *   mensajería, identidad), por flujo que cruza un límite y a nivel de cuenta.
 * - Cada amenaza trae controles: unos se DETECTAN en el diagrama (p. ej. un WAF asociado,
 *   cifrado activo) y otros son MANUALES (el arquitecto los marca como implementados).
 * - El estado se calcula de los controles y el arquitecto puede aceptar el riesgo o
 *   marcarla como "no aplica" con una justificación.
 */
import { cloudText, getService, lid, primaryCloud } from '../catalog/catalog';
import { ancestors, byId, isService, placementOf } from '../lib/graph';
import { profileFor } from '../sim/profiles';
import type { ScenarioKind } from '../sim/scenarios';
import type { AppEdge, AppNode, ConnData, Fix, Role, SecurityGroup, ServiceNode, ThreatState } from '../types';
import { CONTROL_SETTING, SETTING_MAP } from '../security/settings';
import { effectiveNet, isAnyCidr, listenersOf } from '../net/model';

export type Stride = 'S' | 'T' | 'R' | 'I' | 'D' | 'E';
export const STRIDE: Record<Stride, { name: string; es: string; property: string; color: string }> = {
  S: { name: 'Spoofing', es: 'Suplantación', property: 'Autenticación', color: '#6250d6' },
  T: { name: 'Tampering', es: 'Manipulación', property: 'Integridad', color: '#eb6834' },
  R: { name: 'Repudiation', es: 'Repudio', property: 'No repudio', color: '#8a8f98' },
  I: { name: 'Information disclosure', es: 'Divulgación', property: 'Confidencialidad', color: '#2a78d6' },
  D: { name: 'Denial of service', es: 'Denegación de servicio', property: 'Disponibilidad', color: '#d03b3b' },
  E: { name: 'Elevation of privilege', es: 'Elevación de privilegios', property: 'Autorización', color: '#1baf7a' },
};

export type RiskLevel = 'Bajo' | 'Medio' | 'Alto' | 'Crítico';
export type ThreatStatus = 'abierta' | 'parcial' | 'mitigada' | 'aceptada' | 'no-aplica';
export const STATUS_LABEL: Record<ThreatStatus, string> = { abierta: 'Abierta', parcial: 'Parcial', mitigada: 'Mitigada', aceptada: 'Riesgo aceptado', 'no-aplica': 'No aplica' };

export interface Control {
  key: string;
  label: string;
  /** true = se detecta en el diagrama; false = el arquitecto lo marca. */
  auto: boolean;
  /** Para controles automáticos: si se detectó. Para manuales: si está marcado. */
  ok: boolean;
  /** Si no es obligatorio, mejora la postura pero no bloquea "mitigada". */
  required: boolean;
  /** Controles con el mismo grupo son alternativos: basta uno. */
  group?: string;
  hint?: string;
  fix?: Fix;
  /** Ajustes de «Seguridad del proyecto» que cumplen este control. */
  setting?: string[];
  /** Origen del dato: diagrama, red configurada o ajuste del proyecto. */
  source?: 'diagrama' | 'red' | 'proyecto' | 'manual';
}

export interface Threat {
  id: string;
  ruleId: string;
  stride: Stride[];
  title: string;
  description: string;
  kind: 'element' | 'flow' | 'account';
  nodeIds: string[];
  edgeId?: string;
  element: string;
  boundary?: string;
  likelihood: 1 | 2 | 3;
  impact: 1 | 2 | 3;
  score: number;
  risk: RiskLevel;
  controls: Control[];
  status: ThreatStatus;
  computedStatus: ThreatStatus;
  note?: string;
  owner?: string;
  refs: string[];
  sim?: { kind: ScenarioKind; targetId?: string; label: string };
}

/* ───────────────────────────── zonas de confianza */

export type TrustZoneId = 'internet' | 'corporate' | 'edge' | 'aws' | 'vpc-public' | 'vpc-private' | 'vpc-data' | `custom:${string}`;
export const ZONE_INFO: Record<string, { label: string; trust: number }> = {
  internet: { label: 'Internet', trust: 0 },
  corporate: { label: 'Red corporativa', trust: 1 },
  edge: { label: 'Borde AWS', trust: 1 },
  aws: { label: 'Servicios AWS', trust: 2 },
  'vpc-public': { label: 'Subnet pública', trust: 2 },
  'vpc-private': { label: 'Subnet privada', trust: 3 },
  'vpc-data': { label: 'Subnet de datos', trust: 4 },
};

export function trustZone(n: ServiceNode, map: Map<string, AppNode>, cloud: 'aws' | 'azure' = 'aws'): { id: TrustZoneId; label: string; trust: number } {
  const z = (id: TrustZoneId) => ({ id, ...ZONE_INFO[id], label: cloud === 'azure' ? ZONE_INFO[id].label.replace('AWS', 'Azure') : ZONE_INFO[id].label });
  const d = getService(n.data.serviceId);
  if (lid(n) === 'onprem') return { id: 'corporate', ...ZONE_INFO.corporate };
  if (d.role === 'actor' || d.role === 'external') return { id: 'internet', ...ZONE_INFO.internet };
  const custom = ancestors(n, map).find((z) => z.data.zoneKind === 'boundary');
  const place = placementOf(n, map);
  const base: TrustZoneId = place === 'subnet-public' ? 'vpc-public' : place === 'subnet-private' ? 'vpc-private' : place === 'subnet-data' ? 'vpc-data' : place === 'region' ? 'aws' : 'edge';
  if (custom && base !== 'vpc-public' && base !== 'vpc-private' && base !== 'vpc-data') return { id: `custom:${custom.id}`, label: custom.data.label, trust: 2 };
  return z(base);
}

export interface Boundary {
  edgeId: string;
  from: string;
  to: string;
  label: string;
  inbound: boolean;
}

/* ───────────────────────────── riesgo */

export function riskOf(l: number, i: number): { score: number; risk: RiskLevel } {
  const score = l * i;
  return { score, risk: score >= 9 ? 'Crítico' : score >= 6 ? 'Alto' : score >= 3 ? 'Medio' : 'Bajo' };
}
const DATA_IMPACT: Record<string, 1 | 2 | 3> = { Público: 1, Interno: 2, Confidencial: 3, Restringido: 3 };

const MANAGED_API_ROLES: Role[] = ['queue', 'topic', 'eventbus', 'stream', 'secrets', 'kms', 'ai', 'identity', 'observability', 'workflow'];
const CONTROL_PLANE: Role[] = ['observability', 'kms', 'cert', 'waf', 'registry', 'devops'];
const TLS_RE = /https|tls|ssl|oidc|443|wss|grpcs|dns/i;

/* ───────────────────────────── generación */

export function buildThreats(
  nodes: AppNode[],
  edges: AppEdge[],
  state: Record<string, ThreatState> = {},
  opts: { security?: Record<string, boolean>; securityGroups?: SecurityGroup[] } = {},
): { threats: Threat[]; boundaries: Boundary[] } {
  const map = byId(nodes);
  const sec = opts.security ?? {};
  const net = effectiveNet(nodes, edges, opts.securityGroups);
  const services = nodes.filter(isService);
  if (!services.length) return { threats: [], boundaries: [] };
  const ids = new Set(services.map((n) => n.id));
  const E = edges.filter((e) => ids.has(e.source) && ids.has(e.target));
  const svc = (id: string) => map.get(id) as ServiceNode;
  const role = (n: ServiceNode) => getService(n.data.serviceId).role;
  const sid = (n: ServiceNode) => lid(n);
  const out = (n: ServiceNode) => E.filter((e) => e.source === n.id).map((e) => ({ e, t: svc(e.target) }));
  const inc = (n: ServiceNode) => E.filter((e) => e.target === n.id).map((e) => ({ e, s: svc(e.source) }));
  const ofSid = (x: string) => services.filter((n) => sid(n) === x);
  const has = (x: string) => ofSid(x).length > 0;
  const cloud = primaryCloud(nodes);
  const zone = (n: ServiceNode) => trustZone(n, map, cloud);
  const threats: Threat[] = [];

  // Arreglos reutilizables
  const addOrConnect = (serviceId: string, from: ServiceNode | null, to: ServiceNode | null, label: string): Fix => {
    const existing = ofSid(serviceId)[0];
    if (existing) {
      return {
        label: label.replace('Agregar', 'Conectar'),
        connect: [from ? { source: from.id, target: existing.id } : to ? { source: existing.id, target: to.id } : { source: existing.id, target: existing.id }].filter((c) => c.source !== c.target),
      };
    }
    return {
      label,
      // Sin "parent": el store la ubica en la zona que corresponde (p. ej. Cognito dentro de la región)
      add: [{ serviceId, near: (from ?? to)?.id }],
      connect: from ? [{ source: from.id, target: 'new:0' }] : to ? [{ source: 'new:0', target: to.id }] : [],
    };
  };
  const setProps = (n: ServiceNode, props: Record<string, string | number | boolean>, label: string): Fix => ({ label, setProps: [{ nodeId: n.id, props }] });

  type InControl = Omit<Control, 'ok'> & { ok?: boolean };
  const push = (t: Omit<Threat, 'score' | 'risk' | 'status' | 'computedStatus' | 'controls'> & { controls: InControl[] }) => {
    const st = state[t.id] ?? {};
    const controls: Control[] = t.controls.map((c) => {
      const setting = c.setting ?? (!c.auto ? CONTROL_SETTING[c.key] : undefined);
      if (setting?.length) {
        const on = setting.some((k) => sec[k]) || (c.auto ? !!c.ok : false) || !!st.controls?.[c.key];
        const first = setting[0];
        return { ...c, auto: true, ok: on, setting, source: c.auto && c.ok ? c.source ?? 'diagrama' : 'proyecto', fix: on ? undefined : c.fix ?? { label: `Activar: ${SETTING_MAP.get(first)?.label ?? first}`, security: { [first]: true } } };
      }
      return { ...c, ok: c.auto ? !!c.ok : !!st.controls?.[c.key], source: c.source ?? (c.auto ? 'diagrama' : 'manual') };
    });
    // Estado calculado: todos los obligatorios cumplidos (en grupos basta uno)
    const required = controls.filter((c) => c.required);
    const groups = new Map<string, boolean>();
    let allOk = true;
    for (const c of required) {
      if (c.group) groups.set(c.group, (groups.get(c.group) ?? false) || c.ok);
      else if (!c.ok) allOk = false;
    }
    for (const v of groups.values()) if (!v) allOk = false;
    const anyOk = controls.some((c) => c.ok);
    const computedStatus: ThreatStatus = required.length && allOk ? 'mitigada' : anyOk ? 'parcial' : 'abierta';
    const { score, risk } = riskOf(t.likelihood, t.impact);
    threats.push({ ...t, controls, score, risk, computedStatus, status: st.status ?? computedStatus, note: st.note, owner: st.owner });
  };

  // ── Datos de la red configurada (⛨ Red) para los controles que dependen de los Security Groups
  const sgsOf = (n: ServiceNode) => net.sgIdsOf(n).map((id) => net.groups.find((g) => g.id === id)).filter((g): g is SecurityGroup => !!g);
  /** El SG de la pieza solo acepta tráfico desde otros SG (no desde rangos de IP abiertos). */
  const onlyFromSgs = (n: ServiceNode) => {
    const gs = sgsOf(n);
    if (!gs.length) return false;
    const rules = gs.flatMap((g) => g.inbound);
    return rules.length > 0 && rules.every((r) => r.peer.kind === 'sg' && r.protocol !== 'all');
  };
  const onlyFromCdn = (n: ServiceNode) => {
    const gs = sgsOf(n);
    const rules = gs.flatMap((g) => g.inbound);
    return gs.length > 0 && rules.length > 0 && rules.every((r) => r.peer.kind === 'prefix' || r.peer.kind === 'sg' || (r.peer.kind === 'cidr' && !isAnyCidr(r.peer.value)));
  };

  // ── Puntos de entrada expuestos a Internet (resolviendo DNS)
  const actors = services.filter((n) => role(n) === 'actor');
  const externals = services.filter((n) => role(n) === 'external');
  const entrySet = new Set<string>();
  for (const a of [...actors, ...externals]) {
    for (const { t } of out(a)) {
      if (role(t) === 'dns') out(t).forEach(({ t: x }) => entrySet.add(x.id));
      else if (!['identity', 'actor'].includes(role(t))) entrySet.add(t.id);
    }
  }
  const entries = [...entrySet].map(svc).filter((n) => n && !['external', 'actor', 'analytics'].includes(role(n)));
  const wafOf = (n: ServiceNode) => inc(n).find(({ s }) => sid(s) === 'waf')?.s;
  const shieldOf = (n: ServiceNode) => inc(n).find(({ s }) => sid(s) === 'shield')?.s;
  const cdnBefore = (n: ServiceNode) => role(n) === 'cdn' || inc(n).some(({ s }) => role(s) === 'cdn');
  const anyWaf = ofSid('waf')[0];
  const idp = services.find((n) => role(n) === 'identity');

  /* ── A. Cuenta */
  push({
    id: 'acct-audit',
    ruleId: 'acct-audit',
    stride: ['R'],
    title: 'Acciones en la cuenta AWS sin auditoría',
    description: 'Sin un registro de las llamadas a la API de AWS no se puede reconstruir qué pasó en un incidente ni quién lo hizo. Un atacante con acceso suele intentar desactivar los logs.',
    kind: 'account',
    nodeIds: [],
    element: 'Cuenta AWS',
    likelihood: 2,
    impact: 2,
    refs: ['OWASP A09:2021', 'ATT&CK T1562.008'],
    controls: [
      { key: 'cloudtrail', label: 'AWS CloudTrail activo en todas las regiones', auto: true, ok: has('cloudtrail'), required: true, fix: has('cloudtrail') ? undefined : { label: 'Agregar CloudTrail', add: [{ serviceId: 'cloudtrail' }] } },
      { key: 'immutable', label: 'Logs en un bucket con bloqueo de objetos (inmutables) o en una cuenta de log aparte', auto: false, required: false },
    ],
  });
  push({
    id: 'acct-detect',
    ruleId: 'acct-detect',
    stride: ['T', 'E'],
    title: 'Compromiso de credenciales de la cuenta sin detección',
    description: 'Claves filtradas, accesos desde ubicaciones anómalas o minería de criptomonedas pueden pasar días sin que nadie lo note.',
    kind: 'account',
    nodeIds: [],
    element: 'Cuenta AWS',
    likelihood: 2,
    impact: 3,
    refs: ['ATT&CK T1078.004', 'CIS AWS 3.x'],
    controls: [
      { key: 'guardduty', label: 'Amazon GuardDuty activo', auto: true, ok: has('guardduty'), required: true, fix: has('guardduty') ? undefined : { label: 'Agregar GuardDuty', add: [{ serviceId: 'guardduty' }] } },
      { key: 'root-mfa', label: 'MFA en el usuario root y acceso humano por SSO (IAM Identity Center)', auto: false, required: true },
      { key: 'alerts', label: 'Hallazgos enviados al equipo de respuesta (EventBridge → SNS / SIEM)', auto: false, required: false },
    ],
  });

  /* ── B. Actores */
  for (const a of actors) {
    const flows = out(a);
    if (!flows.length) continue;
    const isAdmin = sid(a) === 'admin';
    const authed = flows.some(({ t }) => role(t) === 'identity') || entries.some((en) => out(en).some(({ t }) => role(t) === 'identity'));
    const mfa = idp ? String(idp.data.props.mfa ?? 'OPTIONAL') : 'OFF';
    push({
      id: `actor-spoof:${a.id}`,
      ruleId: 'actor-spoof',
      stride: ['S'],
      title: `Suplantación de ${a.data.label}`,
      description: `Un atacante se hace pasar por ${a.data.label} con credenciales robadas, sesiones secuestradas o sin necesidad de autenticarse.`,
      kind: 'element',
      nodeIds: [a.id],
      element: a.data.label,
      likelihood: 3,
      impact: isAdmin ? 3 : 2,
      refs: ['OWASP A07:2021', 'ATT&CK T1078', 'ATT&CK T1110'],
      controls: [
        { key: 'idp', label: 'Autenticación con un proveedor de identidad (OIDC)', auto: true, ok: authed, required: true, fix: authed ? undefined : addOrConnect('cognito', entries.find((x) => role(x) === 'api') ?? null, null, 'Agregar Cognito') },
        { key: 'mfa', label: isAdmin ? 'MFA obligatorio para administradores' : 'MFA disponible para los usuarios', auto: true, ok: isAdmin ? mfa === 'ON' : mfa !== 'OFF', required: isAdmin, fix: idp && (isAdmin ? mfa !== 'ON' : mfa === 'OFF') ? setProps(idp, { mfa: isAdmin ? 'ON' : 'OPTIONAL' }, isAdmin ? 'Hacer MFA obligatorio' : 'Activar MFA opcional') : undefined },
        { key: 'session', label: 'Sesiones cortas, cookies Secure/HttpOnly y revocación de tokens', auto: false, required: false },
      ],
    });
    push({
      id: `actor-repud:${a.id}`,
      ruleId: 'actor-repud',
      stride: ['R'],
      title: `${a.data.label} puede negar sus acciones`,
      description: 'Sin un registro de auditoría del negocio no es posible demostrar quién hizo una operación (un pago, un cambio de datos, un borrado).',
      kind: 'element',
      nodeIds: [a.id],
      element: a.data.label,
      likelihood: 2,
      impact: isAdmin ? 3 : 2,
      refs: ['OWASP A09:2021'],
      controls: [
        { key: 'applogs', label: 'La aplicación envía logs a CloudWatch', auto: true, ok: services.some((n) => role(n) === 'compute' && out(n).some(({ t }) => role(t) === 'observability')), required: true },
        { key: 'audit', label: 'Auditoría de negocio: quién, qué, cuándo y desde dónde, con retención definida', auto: false, required: true },
      ],
    });
  }

  /* ── C. Sistemas externos */
  for (const x of externals) {
    const inbound = out(x).filter(({ t }) => !['actor'].includes(role(t)));
    if (inbound.length) {
      const entry = inbound[0].t;
      push({
        id: `ext-spoof:${x.id}`,
        ruleId: 'ext-spoof',
        stride: ['S', 'T'],
        title: `Llamadas falsificadas haciéndose pasar por ${x.data.label}`,
        description: `Cualquiera puede enviar una petición que dice venir de ${x.data.label} (por ejemplo, un webhook de pago confirmado) si no se verifica su origen.`,
        kind: 'element',
        nodeIds: [x.id, entry.id],
        element: x.data.label,
        likelihood: 2,
        impact: 3,
        refs: ['CWE-345', 'OWASP A07:2021'],
        controls: [
          { key: 'sig', label: 'Verificar firma HMAC, mTLS o token del emisor en cada llamada', auto: false, required: true },
          { key: 'replay', label: 'Rechazar repeticiones (timestamp + nonce / idempotencia)', auto: false, required: false },
          { key: 'waf', label: 'WAF en el punto de entrada', auto: true, ok: !!wafOf(entry), required: false },
        ],
      });
    }
    const callers = inc(x).filter(({ s }) => role(s) === 'compute' || role(s) === 'workflow');
    for (const { e, s } of callers.slice(0, 1)) {
      const proto = String((e.data as ConnData)?.protocol ?? '');
      push({
        id: `ext-leak:${x.id}`,
        ruleId: 'ext-leak',
        stride: ['I', 'D'],
        title: `Datos y disponibilidad dependientes de ${x.data.label}`,
        description: `${s.data.label} envía datos a un tercero. Una filtración del tercero o un canal sin cifrar expone esos datos, y si el tercero falla puede arrastrar a tu sistema.`,
        kind: 'element',
        nodeIds: [x.id, s.id],
        element: x.data.label,
        likelihood: 2,
        impact: 2,
        refs: ['OWASP A02:2021', 'CWE-319'],
        controls: [
          { key: 'tls', label: 'Conexión cifrada (HTTPS/TLS)', auto: true, ok: TLS_RE.test(proto) || proto === '', required: true },
          { key: 'minimize', label: 'Enviar solo los datos mínimos necesarios (sin datos personales innecesarios)', auto: false, required: true },
          { key: 'resilience', label: 'Timeouts, reintentos con backoff y circuit breaker (o una cola en medio)', auto: false, required: true },
          { key: 'egress', label: 'Control de salida: allowlist de dominios (Network Firewall / proxy)', auto: true, ok: has('networkfirewall'), required: false, fix: has('networkfirewall') ? undefined : { label: 'Agregar Network Firewall', add: [{ serviceId: 'networkfirewall' }] } },
        ],
        sim: { kind: 'node-outage', targetId: x.id, label: 'Simular caída del tercero' },
      });
    }
  }

  /* ── D. Puntos de entrada */
  for (const en of entries) {
    const r = role(en);
    const waf = wafOf(en);
    const wp = waf?.data.props ?? {};
    const managedEdge = ['cdn', 'api', 'lb', 'dns'].includes(r);
    push({
      id: `entry-dos:${en.id}`,
      ruleId: 'entry-dos',
      stride: ['D'],
      title: `Denegación de servicio contra ${en.data.label}`,
      description: 'Inundaciones de red (L3/L4) o de requests HTTP (L7) que agotan la capacidad del punto de entrada o de lo que hay detrás, o que disparan costos ("denial of wallet").',
      kind: 'element',
      nodeIds: [en.id],
      element: en.data.label,
      likelihood: 3,
      impact: 3,
      refs: ['ATT&CK T1498', 'ATT&CK T1499', 'OWASP API4:2023'],
      controls: [
        { key: 'shield', label: 'Protección L3/L4 (Shield Standard en CloudFront, ALB o API Gateway)', auto: true, ok: managedEdge, required: true, hint: managedEdge ? undefined : 'Pon CloudFront, un balanceador o API Gateway delante.' },
        { key: 'ratelimit', label: 'WAF con regla de rate limit por IP', auto: true, ok: !!waf && Number(wp.rateLimit) > 0, required: true, fix: waf ? undefined : addOrConnect('waf', null, en, 'Agregar WAF') },
        { key: 'cdn', label: 'CDN delante que absorbe y cachea', auto: true, ok: cdnBefore(en), required: false },
        { key: 'shieldadv', label: 'Shield Advanced (mitigación L7 automática y protección de costos)', auto: true, ok: !!shieldOf(en), required: false },
        { key: 'alarms', label: 'Alarmas de tráfico anómalo y runbook de respuesta a DDoS', auto: false, required: false },
      ],
      sim: { kind: 'ddos-l7', targetId: en.id, label: 'Simular HTTP flood' },
    });
    if (r !== 'dns') {
      push({
        id: `entry-inject:${en.id}`,
        ruleId: 'entry-inject',
        stride: ['T', 'I', 'E'],
        title: `Inyección y ataques OWASP a través de ${en.data.label}`,
        description: 'SQL injection, XSS, path traversal o inyección de comandos enviados en parámetros, cabeceras o cuerpo para leer o alterar datos o ejecutar código.',
        kind: 'element',
        nodeIds: [en.id],
        element: en.data.label,
        likelihood: 3,
        impact: 3,
        refs: ['OWASP A03:2021', 'CWE-89', 'CWE-79', 'CWE-22', 'ATT&CK T1190'],
        controls: [
          { key: 'crs', label: 'WAF con Core Rule Set (OWASP)', auto: true, ok: !!waf && wp.managedRules !== false, required: true, fix: !waf ? addOrConnect('waf', null, en, 'Agregar WAF') : wp.managedRules === false ? setProps(waf, { managedRules: true }, 'Activar Core Rule Set') : undefined },
          { key: 'sqli', label: 'WAF con reglas de inyección SQL', auto: true, ok: !!waf && wp.sqliRules !== false, required: true, fix: waf && wp.sqliRules === false ? setProps(waf, { sqliRules: true }, 'Activar reglas SQLi') : undefined },
          { key: 'code', label: 'Validación de entradas, consultas parametrizadas y output encoding en el código', auto: false, required: true },
          { key: 'sast', label: 'SAST/DAST en el pipeline de CI', auto: false, required: false },
        ],
        sim: { kind: 'web-attacks', targetId: en.id, label: 'Simular ataques web' },
      });
      push({
        id: `entry-bots:${en.id}`,
        ruleId: 'entry-bots',
        stride: ['S', 'D'],
        title: `Bots: credential stuffing y scraping contra ${en.data.label}`,
        description: 'Bots que prueban credenciales filtradas en el login, crean cuentas falsas o extraen el contenido y los precios.',
        kind: 'element',
        nodeIds: [en.id],
        element: en.data.label,
        likelihood: 3,
        impact: 2,
        refs: ['ATT&CK T1110.004', 'OWASP API6:2023'],
        controls: [
          { key: 'botcontrol', label: 'WAF Bot Control', auto: true, ok: !!waf && !!wp.botControl, required: true, group: 'bots', fix: waf && !wp.botControl ? setProps(waf, { botControl: true }, 'Activar Bot Control') : undefined },
          { key: 'captcha', label: 'CAPTCHA o challenge en login, registro y recuperación de contraseña', auto: false, required: true, group: 'bots' },
          { key: 'ratelimit', label: 'Rate limit por IP en el WAF', auto: true, ok: !!waf, required: false },
        ],
        sim: { kind: 'web-attacks', targetId: en.id, label: 'Simular bots' },
      });
      const tlsIn = inc(en).some(({ e }) => TLS_RE.test(String((e.data as ConnData)?.protocol ?? '')));
      const acm = inc(en).some(({ s }) => sid(s) === 'acm');
      push({
        id: `entry-tls:${en.id}`,
        ruleId: 'entry-tls',
        stride: ['I', 'T'],
        title: `Tráfico de usuarios sin cifrar hacia ${en.data.label}`,
        description: 'Sin TLS, credenciales y datos viajan en claro y pueden ser leídos o modificados en redes públicas (Wi‑Fi, ISP).',
        kind: 'element',
        nodeIds: [en.id],
        element: en.data.label,
        likelihood: 2,
        impact: 2,
        refs: ['OWASP A02:2021', 'CWE-319'],
        controls: [
          { key: 'tls', label: 'HTTPS con certificado TLS (ACM)', auto: true, ok: tlsIn || acm || r === 'api', required: true, fix: tlsIn || acm ? undefined : addOrConnect('acm', null, en, 'Agregar certificado ACM') },
          (() => {
            const ls = role(en) === 'lb' ? listenersOf(en) : [];
            const ok = role(en) === 'cdn' || role(en) === 'api' || (ls.some((l) => l.protocol === 'HTTPS' && l.cert) && ls.filter((l) => l.protocol === 'HTTP').every((l) => l.action === 'redirect-https'));
            return { key: 'hsts', label: 'Redirección HTTP→HTTPS, HSTS y TLS 1.2+', auto: true, ok, required: false, source: 'red' as const, hint: ok ? undefined : 'Configura los listeners en Propiedades → Red: HTTPS con certificado y el 80 redirigiendo a HTTPS.' };
          })(),
        ],
      });
    }
  }

  // Origen accesible saltándose CloudFront
  for (const lb of services.filter((n) => role(n) === 'lb' && n.data.props.scheme === 'internet-facing' && inc(n).some(({ s }) => role(s) === 'cdn'))) {
    const cdnWaf = inc(lb).map(({ s }) => s).filter((s) => role(s) === 'cdn').some((c) => !!wafOf(c));
    if (!cdnWaf) continue;
    push({
      id: `origin-bypass:${lb.id}`,
      ruleId: 'origin-bypass',
      stride: ['E', 'D'],
      title: `Se puede atacar ${lb.data.label} saltándose CloudFront y su WAF`,
      description: 'El balanceador es público: un atacante que descubre su DNS lo ataca directamente y evita todas las reglas configuradas en CloudFront.',
      kind: 'element',
      nodeIds: [lb.id],
      element: lb.data.label,
      likelihood: 3,
      impact: 3,
      refs: ['ATT&CK T1190', 'AWS: restricting access to ALB origins'],
      controls: [
        { key: 'restrict', label: 'Security group del ALB solo con la prefix list de CloudFront (o cabecera secreta validada)', auto: true, ok: onlyFromCdn(lb), required: true, group: 'origin', source: 'red', hint: onlyFromCdn(lb) ? undefined : 'En ⛨ Red, el grupo del balanceador acepta tráfico de cualquier IP: quita esa regla y deja solo la de CloudFront.' },
        { key: 'waf-alb', label: 'WAF asociado también al balanceador', auto: true, ok: !!wafOf(lb), required: true, group: 'origin', fix: wafOf(lb) ? undefined : anyWaf ? { label: 'Asociar el WAF también al ALB', connect: [{ source: anyWaf.id, target: lb.id }] } : undefined },
      ],
      sim: { kind: 'ddos-l7', targetId: lb.id, label: 'Simular ataque directo al ALB' },
    });
  }

  // APIs sin autenticación
  for (const api of services.filter((n) => role(n) === 'api')) {
    const authorizer = out(api).some(({ t }) => role(t) === 'identity');
    push({
      id: `api-auth:${api.id}`,
      ruleId: 'api-auth',
      stride: ['S', 'E'],
      title: `${api.data.label}: autenticación y autorización por recurso`,
      description: 'Endpoints sin autenticación, o que no verifican que el recurso pedido pertenezca al usuario (BOLA/IDOR), permiten leer o modificar datos de otros.',
      kind: 'element',
      nodeIds: [api.id],
      element: api.data.label,
      likelihood: 3,
      impact: 3,
      refs: ['OWASP API1:2023 (BOLA)', 'OWASP API2:2023', 'OWASP A01:2021'],
      controls: [
        { key: 'authorizer', label: 'Authorizer JWT/OIDC en la API', auto: true, ok: authorizer, required: true, fix: authorizer ? undefined : addOrConnect('cognito', api, null, 'Agregar Cognito como authorizer') },
        { key: 'bola', label: 'Autorización por objeto: el usuario solo accede a sus propios recursos', auto: false, required: true },
        { key: 'quota', label: 'Throttling y cuotas por cliente (usage plans)', auto: true, ok: api.data.props.rateLimit !== undefined, required: false, hint: 'Se configura en la sección «Escalado» de la API (límite y ráfaga).', fix: api.data.props.rateLimit !== undefined ? undefined : setProps(api, { rateLimit: 1000, burstLimit: 500 }, 'Limitar a 1.000 req/s') },
      ],
    });
  }

  /* ── E. Cómputo */
  for (const c of services.filter((n) => role(n) === 'compute')) {
    const place = placementOf(c, map);
    const p = profileFor(c);
    const outs = out(c);
    if (place === 'subnet-public') {
      push({
        id: `comp-public:${c.id}`,
        ruleId: 'comp-public',
        stride: ['E', 'I'],
        title: `${c.data.label} está en una subnet pública`,
        description: 'El cómputo en una subnet pública puede recibir IP pública y quedar alcanzable desde Internet, saltándose el balanceador y el WAF.',
        kind: 'element',
        nodeIds: [c.id],
        element: c.data.label,
        likelihood: 3,
        impact: 3,
        refs: ['ATT&CK T1190', 'CIS AWS 5.x'],
        controls: [{ key: 'private', label: 'Mover a una subnet privada (arrástralo a la zona)', auto: true, ok: false, required: true, hint: 'Arrastra la pieza a una subnet privada en el lienzo.' }],
      });
    }
    const dbTargets = outs.filter(({ t }) => ['rds', 'aurora', 'documentdb', 'redshift', 'opensearch', 'elasticache'].includes(sid(t)) || role(t) === 'external');
    if (dbTargets.length) {
      const secretsEdge = outs.find(({ t }) => sid(t) === 'secrets');
      const sm = secretsEdge?.t ?? ofSid('secrets')[0];
      push({
        id: `comp-secrets:${c.id}`,
        ruleId: 'comp-secrets',
        stride: ['I', 'E'],
        title: `Credenciales de ${c.data.label} expuestas en código o variables`,
        description: 'Contraseñas de BD o API keys en el código, el repositorio o variables de entorno en texto plano se filtran por logs, dumps o accesos al repositorio.',
        kind: 'element',
        nodeIds: [c.id],
        element: c.data.label,
        likelihood: 2,
        impact: 3,
        refs: ['CWE-798', 'OWASP A07:2021', 'ATT&CK T1552'],
        controls: [
          { key: 'secrets', label: 'Lee las credenciales de Secrets Manager', auto: true, ok: !!secretsEdge, required: true, fix: secretsEdge ? undefined : addOrConnect('secrets', c, null, 'Agregar Secrets Manager') },
          { key: 'rotation', label: 'Rotación automática de credenciales', auto: true, ok: !!sm && sm.data.props.rotation !== false, required: false, fix: sm && sm.data.props.rotation === false ? setProps(sm, { rotation: true }, 'Activar rotación') : undefined },
          { key: 'scan', label: 'Escaneo de secretos en el repositorio (pre‑commit / CI)', auto: false, required: false },
        ],
      });
    }
    push({
      id: `comp-iam:${c.id}`,
      ruleId: 'comp-iam',
      stride: ['E'],
      title: `Permisos IAM excesivos en ${c.data.label}`,
      description: 'Si el código se compromete, el atacante hereda los permisos del rol. Con comodines (*) puede leer todos los buckets, borrar tablas o moverse a otros servicios.',
      kind: 'element',
      nodeIds: [c.id],
      element: c.data.label,
      likelihood: 2,
      impact: 3,
      refs: ['OWASP A01:2021', 'ATT&CK T1078.004', 'CWE-250'],
      controls: [
        { key: 'least', label: 'Rol con mínimo privilegio, sin comodines (lo genera el Terraform a partir de las flechas)', auto: true, ok: true, required: true },
        { key: 'boundary', label: 'Permission boundary o SCP que limite el máximo', auto: false, required: false },
      ],
    });
    const isContainer = ['ecs', 'eks'].includes(sid(c));
    const ecrLinked = inc(c).some(({ s }) => sid(s) === 'ecr');
    push({
      id: `comp-vuln:${c.id}`,
      ruleId: 'comp-vuln',
      stride: ['T', 'E'],
      title: `Vulnerabilidades explotables en ${c.data.label}`,
      description: 'Librerías, imagen base o sistema operativo con CVEs conocidos permiten ejecución remota de código y persistencia en la carga de trabajo.',
      kind: 'element',
      nodeIds: [c.id],
      element: c.data.label,
      likelihood: 2,
      impact: 3,
      refs: ['OWASP A06:2021', 'ATT&CK T1190'],
      controls: [
        ...(isContainer ? [{ key: 'ecr', label: 'Imágenes desde ECR con escaneo al subir', auto: true, ok: ecrLinked, required: true, fix: ecrLinked ? undefined : addOrConnect('ecr', null, c, 'Agregar ECR') }] : []),
        { key: 'patch', label: sid(c) === 'ec2' ? 'Parcheo del SO (SSM Patch Manager) y Amazon Inspector' : 'Escaneo de dependencias (SCA) en CI y actualización continua', auto: true, ok: sid(c) === 'ec2' && has('inspector'), required: true, setting: sid(c) === 'ec2' ? ['patching'] : ['sca'] },
        { key: 'runtime', label: 'Detección en tiempo de ejecución (GuardDuty)', auto: true, ok: has('guardduty'), required: false },
        ...(sid(c) === 'ec2' ? [{ key: 'imdsv2', label: 'IMDSv2 obligatorio (lo configura el Terraform exportado)', auto: true, ok: true, required: false }] : []),
      ],
    });
    const logs = outs.some(({ t }) => role(t) === 'observability');
    push({
      id: `comp-logs:${c.id}`,
      ruleId: 'comp-logs',
      stride: ['R'],
      title: `Acciones de ${c.data.label} sin trazabilidad`,
      description: 'Sin logs centralizados no hay evidencia para investigar un incidente ni para detectar abuso.',
      kind: 'element',
      nodeIds: [c.id],
      element: c.data.label,
      likelihood: 2,
      impact: 2,
      refs: ['OWASP A09:2021'],
      controls: [
        { key: 'logs', label: 'Logs centralizados en CloudWatch', auto: true, ok: logs, required: true, fix: logs ? undefined : addOrConnect('cloudwatch', c, null, 'Agregar CloudWatch') },
        { key: 'xray', label: 'Trazas distribuidas (X‑Ray)', auto: true, ok: outs.some(({ t }) => sid(t) === 'xray'), required: false },
        { key: 'nosecrets', label: 'Los logs no contienen datos sensibles ni tokens', auto: false, required: false },
      ],
    });
    const scales = p.scale !== 'none';
    push({
      id: `comp-dos:${c.id}`,
      ruleId: 'comp-dos',
      stride: ['D'],
      title: `Agotamiento de capacidad de ${c.data.label}`,
      description: 'Un pico (legítimo o malicioso) o la caída de una instancia deja al servicio sin capacidad suficiente.',
      kind: 'element',
      nodeIds: [c.id],
      element: c.data.label,
      likelihood: 2,
      impact: 2,
      refs: ['ATT&CK T1499', 'Well‑Architected REL'],
      controls: [
        { key: 'autoscale', label: 'Escala automáticamente', auto: true, ok: scales, required: true, fix: !scales && ['ec2', 'ecs', 'eks', 'apprunner'].includes(sid(c)) ? setProps(c, { scalePolicy: 'cpu', autoscaling: true, 'sim.autoscaling': true, ...(sid(c) === 'ec2' ? { count: Math.max(2, Number(c.data.props.count) || 2) } : {}) }, 'Escalar por CPU') : undefined, hint: 'Se configura en la sección «Escalado» de la pieza.' },
        { key: 'multiaz', label: 'Al menos 2 instancias en zonas distintas', auto: true, ok: p.multiAz || sid(c) === 'lambda', required: true, fix: sid(c) === 'ecs' && !p.multiAz ? setProps(c, { desired: 2 }, 'Usar 2 tareas') : sid(c) === 'ec2' && !p.multiAz ? setProps(c, { count: 2, autoscaling: true }, 'Usar 2 instancias') : undefined },
      ],
      sim: { kind: 'spike', label: 'Simular pico de tráfico' },
    });
    for (const { t } of outs.filter(({ t }) => role(t) === 'ai')) {
      push({
        id: `comp-ai:${c.id}:${t.id}`,
        ruleId: 'comp-ai',
        stride: ['T', 'I', 'E'],
        title: `Inyección de prompts y fuga de datos vía ${t.data.label}`,
        description: 'Instrucciones maliciosas en la entrada del usuario o en documentos recuperados manipulan al modelo para filtrar datos, saltarse reglas o disparar acciones con los permisos de la aplicación.',
        kind: 'element',
        nodeIds: [c.id, t.id],
        element: t.data.label,
        likelihood: 3,
        impact: 3,
        refs: ['OWASP LLM01:2025', 'OWASP LLM02:2025', 'OWASP LLM06:2025'],
        controls: [
          { key: 'guardrails', label: 'Guardrails activos en el modelo', auto: true, ok: !!t.data.props.guardrails, required: true, fix: t.data.props.guardrails === false ? setProps(t, { guardrails: true }, 'Activar Guardrails') : undefined },
          { key: 'separate', label: 'Separar instrucciones de datos y validar la salida antes de usarla o ejecutarla', auto: false, required: true },
          { key: 'agency', label: 'Mínimo privilegio en las herramientas/acciones que el modelo puede invocar', auto: false, required: true },
          { key: 'pii', label: 'No enviar secretos ni datos personales innecesarios al modelo', auto: false, required: false },
        ],
      });
    }
  }

  /* ── F. Datos */
  for (const d of services.filter((n) => ['datastore', 'cache', 'search', 'storage'].includes(role(n)))) {
    const s = sid(d);
    const p = d.data.props;
    const cls = String(p.dataClass ?? 'Confidencial');
    const imp = DATA_IMPACT[cls] ?? 3;
    const exposed = inc(d).some(({ s: src }) => ['actor', 'external', 'lb'].includes(role(src)) || (role(src) === 'api' && s !== 'dynamodb') || (role(src) === 'cdn' && s !== 's3'));
    const place = placementOf(d, map);
    const vpcBound = getService(s).vpcBound;
    const encryptable = 'encrypted' in p;
    push({
      id: `ds-access:${d.id}`,
      ruleId: 'ds-access',
      stride: ['I', 'E'],
      title: `Acceso no autorizado a ${d.data.label}`,
      description: `Lectura o exfiltración de los datos (${cls.toLowerCase()}) por exposición de red, políticas permisivas o credenciales comprometidas.`,
      kind: 'element',
      nodeIds: [d.id],
      element: d.data.label,
      likelihood: exposed || p.public ? 3 : 2,
      impact: imp,
      refs: ['OWASP A01:2021', 'ATT&CK T1530', 'CWE-284'],
      controls: [
        { key: 'noinet', label: 'Sin acceso directo desde Internet', auto: true, ok: !exposed, required: true },
        ...(s === 's3' ? [{ key: 'bpa', label: 'Bloqueo de acceso público en el bucket', auto: true, ok: !p.public, required: true, fix: p.public ? setProps(d, { public: false }, 'Bloquear acceso público') : undefined }] : []),
        ...(vpcBound ? [{ key: 'isolated', label: 'En una subnet de datos aislada', auto: true, ok: place === 'subnet-data', required: false, hint: 'Arrástrala a una subnet de datos.' }] : []),
        ...(vpcBound
          ? [{ key: 'least', label: 'Su security group solo acepta tráfico desde el grupo de la aplicación', auto: true, ok: onlyFromSgs(d), required: true, source: 'red' as const, hint: onlyFromSgs(d) ? undefined : 'En ⛨ Red, la pieza acepta tráfico desde rangos de IP (o no tiene grupo). Deja solo el grupo de la aplicación como origen.' }]
          : [{ key: 'least', label: 'Política de recurso / IAM que solo permite a la aplicación (lo genera el Terraform)', auto: true, ok: true, required: true }]),
      ],
    });
    if (encryptable || s === 'dynamodb' || s === 'elasticache') {
      const enc = s === 'dynamodb' || s === 'elasticache' ? true : p.encrypted !== false;
      push({
        id: `ds-encrypt:${d.id}`,
        ruleId: 'ds-encrypt',
        stride: ['I'],
        title: `${d.data.label} sin cifrado en reposo`,
        description: 'Snapshots, backups o discos robados o compartidos por error exponen los datos si no están cifrados.',
        kind: 'element',
        nodeIds: [d.id],
        element: d.data.label,
        likelihood: 1,
        impact: imp,
        refs: ['OWASP A02:2021', 'CWE-311'],
        controls: [
          { key: 'enc', label: 'Cifrado en reposo activo', auto: true, ok: enc, required: true, fix: enc ? undefined : setProps(d, { encrypted: true }, 'Activar cifrado') },
          { key: 'cmk', label: 'Llave KMS administrada por el cliente (CMK) con rotación', auto: true, ok: out(d).some(({ t }) => sid(t) === 'kms'), required: cls === 'Restringido', fix: out(d).some(({ t }) => sid(t) === 'kms') ? undefined : addOrConnect('kms', d, null, 'Agregar llave KMS') },
        ],
      });
    }
    const backups =
      s === 'rds' || s === 'aurora' || s === 'documentdb' || s === 'redshift' ? { ok: true, label: 'Backups automáticos (7 días en el Terraform exportado)' }
      : s === 'dynamodb' ? { ok: p.pitr !== false, label: 'Point‑in‑time recovery', fix: p.pitr === false ? setProps(d, { pitr: true }, 'Activar PITR') : undefined }
      : s === 's3' ? { ok: p.versioning !== false, label: 'Versionado del bucket', fix: p.versioning === false ? setProps(d, { versioning: true }, 'Activar versionado') : undefined }
      : null;
    if (backups && role(d) !== 'cache') {
      push({
        id: `ds-tamper:${d.id}`,
        ruleId: 'ds-tamper',
        stride: ['T'],
        title: `Manipulación, borrado o ransomware en ${d.data.label}`,
        description: 'Un atacante o un error borra o cifra los datos. Sin copias recuperables (idealmente fuera de la cuenta) la pérdida es definitiva.',
        kind: 'element',
        nodeIds: [d.id],
        element: d.data.label,
        likelihood: 2,
        impact: imp,
        refs: ['ATT&CK T1485', 'ATT&CK T1486'],
        controls: [
          { key: 'backup', label: backups.label, auto: true, ok: backups.ok, required: true, fix: (backups as { fix?: Fix }).fix },
          { key: 'offsite', label: 'Copias en otra cuenta o región (AWS Backup con vault lock)', auto: false, required: cls === 'Restringido' },
          { key: 'restore', label: 'Restauración probada periódicamente', auto: false, required: false },
        ],
      });
    }
    push({
      id: `ds-audit:${d.id}`,
      ruleId: 'ds-audit',
      stride: ['R'],
      title: `Accesos a ${d.data.label} sin auditoría`,
      description: 'Sin registro de quién leyó o cambió los datos no se puede detectar ni investigar un abuso interno o una exfiltración.',
      kind: 'element',
      nodeIds: [d.id],
      element: d.data.label,
      likelihood: 2,
      impact: imp >= 3 ? 2 : 1,
      refs: ['OWASP A09:2021'],
      controls: [
        { key: 'trail', label: 'CloudTrail activo', auto: true, ok: has('cloudtrail'), required: true, fix: has('cloudtrail') ? undefined : { label: 'Agregar CloudTrail', add: [{ serviceId: 'cloudtrail' }] } },
        { key: 'datalogs', label: s === 's3' ? 'Data events de S3 en CloudTrail' : 'Logs de auditoría del motor de base de datos', auto: false, required: cls === 'Restringido' },
      ],
    });
    const prof = profileFor(d);
    const managed = ['s3', 'dynamodb'].includes(s);
    push({
      id: `ds-dos:${d.id}`,
      ruleId: 'ds-dos',
      stride: ['D'],
      title: `Indisponibilidad de ${d.data.label}`,
      description: 'La caída del primario o de una zona de disponibilidad deja a la aplicación sin datos hasta que se recupera.',
      kind: 'element',
      nodeIds: [d.id],
      element: d.data.label,
      likelihood: 2,
      impact: role(d) === 'cache' ? 2 : 3,
      refs: ['Well‑Architected REL10'],
      controls: [
        {
          key: 'ha',
          label: managed ? 'Servicio multi‑AZ administrado por AWS' : 'Multi‑AZ o réplica para failover automático',
          auto: true,
          ok: managed || prof.multiAz,
          required: true,
          fix: managed || prof.multiAz ? undefined : s === 'rds' ? setProps(d, { multiAZ: true }, 'Activar Multi‑AZ') : s === 'aurora' || s === 'elasticache' ? setProps(d, { replicas: 1 }, 'Agregar una réplica') : s === 'documentdb' || s === 'opensearch' ? setProps(d, { instances: 2 }, 'Usar 2 instancias') : undefined,
        },
      ],
      sim: prof.stateful ? { kind: 'instance-failure', targetId: d.id, label: 'Simular caída del primario' } : undefined,
    });
    if (s === 'elasticache') {
      push({
        id: `cache-auth:${d.id}`,
        ruleId: 'cache-auth',
        stride: ['S', 'I'],
        title: `Acceso a ${d.data.label} sin autenticación`,
        description: 'Redis/Valkey sin AUTH permite que cualquier proceso con acceso de red lea o envenene la caché (sesiones, tokens).',
        kind: 'element',
        nodeIds: [d.id],
        element: d.data.label,
        likelihood: 2,
        impact: 2,
        refs: ['CWE-306'],
        controls: [
          { key: 'auth', label: 'AUTH token o RBAC de usuarios en ElastiCache', auto: false, required: true },
          { key: 'transit', label: 'Cifrado en tránsito (lo configura el Terraform exportado)', auto: true, ok: true, required: true },
        ],
      });
    }
  }

  /* ── G. Mensajería */
  for (const q of services.filter((n) => ['queue', 'topic', 'eventbus', 'stream'].includes(role(n)))) {
    push({
      id: `msg-poison:${q.id}`,
      ruleId: 'msg-poison',
      stride: ['T', 'S'],
      title: `Mensajes falsificados o envenenados en ${q.data.label}`,
      description: 'Si cualquiera puede publicar, un atacante inyecta eventos falsos (pedidos, pagos) o mensajes malformados que tumban a los consumidores.',
      kind: 'element',
      nodeIds: [q.id],
      element: q.data.label,
      likelihood: 2,
      impact: 2,
      refs: ['CWE-20', 'CWE-345'],
      controls: [
        { key: 'policy', label: 'Política de recurso: solo los productores autorizados publican', auto: false, required: true },
        { key: 'schema', label: 'Validación del esquema del mensaje en el consumidor', auto: false, required: true },
        ...(sid(q) === 'sqs' ? [{ key: 'dlq', label: 'Dead‑letter queue para mensajes que fallan', auto: true, ok: !!q.data.props.dlq, required: false, fix: q.data.props.dlq ? undefined : setProps(q, { dlq: true }, 'Activar DLQ') }] : []),
      ],
    });
  }

  /* ── H. Identidad */
  for (const id of services.filter((n) => role(n) === 'identity')) {
    const mfa = String(id.data.props.mfa ?? 'OPTIONAL');
    push({
      id: `idp-brute:${id.id}`,
      ruleId: 'idp-brute',
      stride: ['S'],
      title: `Fuerza bruta y robo de credenciales en ${id.data.label}`,
      description: 'Ataques de diccionario, credential stuffing o phishing contra el login para tomar cuentas de usuarios.',
      kind: 'element',
      nodeIds: [id.id],
      element: id.data.label,
      likelihood: 3,
      impact: 3,
      refs: ['OWASP A07:2021', 'ATT&CK T1110'],
      controls: [
        { key: 'mfa', label: 'MFA (obligatorio para cuentas privilegiadas)', auto: true, ok: mfa !== 'OFF', required: true, fix: mfa === 'OFF' ? setProps(id, { mfa: 'OPTIONAL' }, 'Activar MFA') : undefined },
        { key: 'password', label: 'Política de contraseñas robusta (12+ caracteres en el Terraform exportado)', auto: true, ok: true, required: false },
        { key: 'threatprot', label: 'Protección ante credenciales comprometidas y bloqueo adaptativo (Cognito threat protection)', auto: true, ok: !!id.data.props.threatProtection, required: true, fix: id.data.props.threatProtection ? undefined : setProps(id, { threatProtection: true }, 'Activar threat protection') },
        { key: 'waf', label: 'WAF delante del flujo de login', auto: true, ok: !!anyWaf, required: false },
      ],
      sim: { kind: 'web-attacks', label: 'Simular bots contra el login' },
    });
  }

  /* ── I. Flujos que cruzan límites de confianza */
  const boundaries: Boundary[] = [];
  for (const e of E) {
    let s = svc(e.source);
    const t = svc(e.target);
    // El DNS solo resuelve: el flujo real va del actor al destino del DNS
    if (role(s) === 'dns') {
      const viaActor = inc(s).map(({ s: a }) => a).find((a) => role(a) === 'actor' || role(a) === 'external');
      if (!viaActor || E.some((x) => x.source === viaActor.id && x.target === t.id)) continue;
      s = viaActor;
    }
    if (CONTROL_PLANE.includes(role(t)) || CONTROL_PLANE.includes(role(s)) || role(t) === 'dns' || role(t) === 'actor') continue;
    const zs = zone(s);
    const zt = zone(t);
    if (zs.id === zt.id) continue;
    const inbound = zt.trust > zs.trust;
    const label = `${zs.label} → ${zt.label}`;
    boundaries.push({ edgeId: e.id, from: zs.label, to: zt.label, label, inbound });
    if (!inbound && zt.id !== 'internet') continue;
    const proto = String((e.data as ConnData)?.protocol ?? '');
    const managedApi = MANAGED_API_ROLES.includes(role(t)) || ['s3', 'dynamodb'].includes(sid(t));
    const isDb = /sql|postgres|mysql|mssql|oracle|redis|mongo|5432|3306|1433|1521|6379|27017|kafka|9098|nfs/i.test(proto);
    const tlsAuto = TLS_RE.test(proto) || managedApi;
    const fromInternet = zs.id === 'internet';
    const toData = zt.id === 'vpc-data' || ['datastore', 'storage', 'cache'].includes(role(t));
    const cls = String(t.data.props.dataClass ?? (toData ? 'Confidencial' : 'Interno'));
    push({
      id: `flow:${e.id}`,
      ruleId: 'flow-transit',
      stride: ['T', 'I'],
      title: `Interceptación o manipulación en ${s.data.label} → ${t.data.label}`,
      description: `El flujo cruza el límite de confianza ${label}. Sin cifrado y autenticación del canal, alguien en la ruta puede leer o alterar los datos${proto ? ` (${proto})` : ''}.`,
      kind: 'flow',
      nodeIds: [s.id, t.id],
      edgeId: e.id,
      element: `${s.data.label} → ${t.data.label}`,
      boundary: label,
      likelihood: fromInternet ? 3 : zs.trust <= 1 ? 2 : 1,
      impact: toData ? (DATA_IMPACT[cls] ?? 3) : 2,
      refs: ['OWASP A02:2021', 'CWE-319', 'ATT&CK T1557'],
      controls: isDb
        ? [
            { key: 'tls', label: 'TLS obligatorio en la conexión (rds.force_ssl / require_secure_transport / transit encryption)', auto: false, required: true },
            { key: 'sg', label: 'Security group que solo acepta el puerto desde el SG de la aplicación', auto: true, ok: onlyFromSgs(t), required: false, source: 'red' as const, hint: onlyFromSgs(t) ? undefined : 'Revisa el grupo de la base de datos en ⛨ Red: tiene orígenes por rango de IP o abiertos.' },
          ]
        : [
            { key: 'tls', label: managedApi && !TLS_RE.test(proto) ? 'Cifrado por la API de AWS (HTTPS)' : 'Cifrado en tránsito (HTTPS/TLS)', auto: !(!tlsAuto && !fromInternet && zs.trust >= 2), ok: tlsAuto, required: true, hint: tlsAuto ? undefined : 'Usa HTTPS en la conexión (edita el protocolo de la flecha) o re‑cifra en el balanceador.' },
            ...(fromInternet ? [] : [{ key: 'authn', label: 'El destino autentica al origen (IAM/SigV4, mTLS o token)', auto: managedApi, ok: managedApi, required: false }]),
          ],
    });
  }

  // Textos en la nube del diagrama
  if (cloud === 'azure') {
    const t = (x: string) => cloudText(x, cloud);
    for (const th of threats) {
      th.title = t(th.title);
      th.description = t(th.description);
      th.element = t(th.element);
      th.controls = th.controls.map((c) => ({ ...c, label: t(c.label), hint: c.hint ? t(c.hint) : c.hint, fix: c.fix ? { ...c.fix, label: t(c.fix.label) } : c.fix }));
    }
  }

  // Orden: riesgo, luego estado
  const order: Record<ThreatStatus, number> = { abierta: 0, parcial: 0, aceptada: 2, mitigada: 3, 'no-aplica': 4 };
  threats.sort((a, b) => order[a.status] - order[b.status] || b.score - a.score || a.title.localeCompare(b.title));
  return { threats, boundaries };
}

export function summarizeThreats(ts: Threat[]) {
  const open = ts.filter((t) => t.status === 'abierta' || t.status === 'parcial');
  return {
    total: ts.length,
    open: open.length,
    critical: open.filter((t) => t.risk === 'Crítico').length,
    high: open.filter((t) => t.risk === 'Alto').length,
    medium: open.filter((t) => t.risk === 'Medio').length,
    low: open.filter((t) => t.risk === 'Bajo').length,
    handled: ts.filter((t) => t.status === 'mitigada' || t.status === 'aceptada' || t.status === 'no-aplica').length,
    byStride: (Object.keys(STRIDE) as Stride[]).map((k) => ({ k, total: ts.filter((t) => t.stride.includes(k)).length, open: open.filter((t) => t.stride.includes(k)).length })),
  };
}

const csvCell = (v: string) => `"${String(v ?? '').replace(/"/g, '""')}"`;
export function threatsToCsv(ts: Threat[]): string {
  const head = ['ID', 'STRIDE', 'Amenaza', 'Elemento', 'Límite de confianza', 'Riesgo', 'Probabilidad', 'Impacto', 'Estado', 'Controles pendientes', 'Controles implementados', 'Referencias', 'Responsable', 'Nota'];
  const rows = ts.map((t) => [
    t.id,
    t.stride.join(''),
    t.title,
    t.element,
    t.boundary ?? '',
    t.risk,
    String(t.likelihood),
    String(t.impact),
    STATUS_LABEL[t.status],
    t.controls.filter((c) => !c.ok && c.required).map((c) => c.label).join(' | '),
    t.controls.filter((c) => c.ok).map((c) => c.label).join(' | '),
    t.refs.join(', '),
    t.owner ?? '',
    t.note ?? '',
  ]);
  return '﻿' + [head, ...rows].map((r) => r.map(csvCell).join(',')).join('\r\n');
}
