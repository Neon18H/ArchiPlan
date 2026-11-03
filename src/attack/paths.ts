/**
 * Rutas de ataque: cómo llegaría un atacante desde Internet hasta los datos más valiosos.
 *
 * Se arma un grafo de movimientos del atacante sobre el diagrama (entrada, explotación,
 * robo de credenciales, abuso de roles IAM, movimiento lateral, acceso a datos). Cada salto
 * se mapea a una técnica de MITRE ATT&CK y su probabilidad baja con los controles presentes
 * (WAF, MFA, validación de entradas, permission boundaries, autenticación entre servicios…),
 * cada uno con su mitigación de MITRE (M10xx).
 *
 * Es un modelo cualitativo para priorizar defensas, no una prueba de penetración.
 */
import { getService, lid, primaryCloud, cloudText } from '../catalog/catalog';
import { byId, isService } from '../lib/graph';
import { analyzeNetwork } from '../net/reach';
import { effectiveNet, isAnyCidr, ruleCovers } from '../net/model';
import type { AppEdge, AppNode, PropValue, SecurityGroup, ServiceNode } from '../types';

export type Tactic = 'Reconocimiento' | 'Acceso inicial' | 'Acceso a credenciales' | 'Escalada de privilegios' | 'Movimiento lateral' | 'Descubrimiento' | 'Recolección' | 'Exfiltración' | 'Impacto';

export const TACTIC_ID: Record<Tactic, string> = {
  Reconocimiento: 'TA0043',
  'Acceso inicial': 'TA0001',
  'Acceso a credenciales': 'TA0006',
  'Escalada de privilegios': 'TA0004',
  'Movimiento lateral': 'TA0008',
  Descubrimiento: 'TA0007',
  Recolección: 'TA0009',
  Exfiltración: 'TA0010',
  Impacto: 'TA0040',
};

export interface Technique {
  id: string;
  name: string;
}

const T = {
  scan: { id: 'T1595.002', name: 'Active Scanning: Vulnerability Scanning' },
  exploit: { id: 'T1190', name: 'Exploit Public-Facing Application' },
  remote: { id: 'T1133', name: 'External Remote Services' },
  stuffing: { id: 'T1110.004', name: 'Brute Force: Credential Stuffing' },
  brute: { id: 'T1110', name: 'Brute Force' },
  validAccounts: { id: 'T1078', name: 'Valid Accounts' },
  cloudAccounts: { id: 'T1078.004', name: 'Valid Accounts: Cloud Accounts' },
  secretsStore: { id: 'T1555.006', name: 'Credentials from Password Stores: Cloud Secrets Management Stores' },
  credFiles: { id: 'T1552.001', name: 'Unsecured Credentials: Credentials In Files' },
  repo: { id: 'T1213', name: 'Data from Information Repositories' },
  cloudStorage: { id: 'T1530', name: 'Data from Cloud Storage' },
  transferAccount: { id: 'T1537', name: 'Transfer Data to Cloud Account' },
  remoteExploit: { id: 'T1210', name: 'Exploitation of Remote Services' },
  manipulation: { id: 'T1565.001', name: 'Data Manipulation: Stored Data Manipulation' },
} satisfies Record<string, Technique>;

export const techUrl = (id: string) => `https://attack.mitre.org/techniques/${id.replace('.', '/')}/`;
export const mitigationUrl = (id: string) => `https://attack.mitre.org/mitigations/${id}/`;

export interface AttackFix {
  label: string;
  security?: string;
  nodeId?: string;
  props?: Record<string, PropValue>;
}

export interface AttackControl {
  /** Mitigación de MITRE (M10xx). */
  mitigation: string;
  label: string;
  ok: boolean;
  /** Cuánto multiplica la probabilidad del salto si está presente. */
  factor: number;
  fix?: AttackFix;
}

export interface AttackStep {
  from: string;
  to: string;
  /** Flechas del diagrama que recorre (vacío = salto sin flecha: rol IAM, credenciales). */
  edgeIds: string[];
  virtual: boolean;
  tactic: Tactic;
  technique: Technique | null;
  how: string;
  likelihood: number;
  controls: AttackControl[];
}

export interface AttackPath {
  id: string;
  targetId: string;
  targetLabel: string;
  /** Valor de lo que se alcanza (1‑5). */
  value: number;
  steps: AttackStep[];
  likelihood: number;
  risk: 'Crítico' | 'Alto' | 'Medio' | 'Bajo';
  title: string;
  /** Control que más baja la probabilidad de la ruta. */
  bestCut: { step: number; control: AttackControl; after: number } | null;
}

export interface AttackResult {
  paths: AttackPath[];
  /** Piezas de valor sin ninguna ruta desde Internet. */
  safeTargets: string[];
  entries: string[];
}

type Mode = 'exec' | 'user' | 'transit' | 'creds' | 'data' | 'start';
interface Ctx {
  mode: Mode;
  waf: Record<string, PropValue> | null;
}

const ROUTERS = ['cdn', 'lb', 'api', 'dns'];
const DATA_ROLES = ['datastore', 'storage', 'search', 'cache'];
const CLASS_VALUE: Record<string, number> = { Restringido: 5, Confidencial: 4, Interno: 2, Público: 1 };

export function buildAttackPaths(nodes: AppNode[], edges: AppEdge[], opts: { security: Record<string, boolean>; securityGroups: SecurityGroup[] }): AttackResult {
  const map = byId(nodes);
  const sec = opts.security;
  const services = nodes.filter(isService);
  const cloud = primaryCloud(nodes);
  const tx = (s: string) => (cloud === 'azure' ? cloudText(s, cloud) : s);
  const role = (n: ServiceNode) => getService(n.data.serviceId).role;
  const label = (id: string) => (map.get(id) as ServiceNode | undefined)?.data.label ?? id;
  const net = analyzeNetwork(nodes, edges, opts.securityGroups);
  const eff = effectiveNet(nodes, edges, opts.securityGroups);
  const allowed = (e: AppEdge) => net.verdicts.get(e.id)?.ok !== false;
  const out = new Map<string, AppEdge[]>();
  for (const e of edges) {
    if (!out.has(e.source)) out.set(e.source, []);
    out.get(e.source)!.push(e);
  }
  const svc = (id: string) => map.get(id) as ServiceNode | undefined;

  // WAF asociado a cada punto de entrada
  const wafOf = new Map<string, Record<string, PropValue>>();
  for (const e of edges) {
    const s = svc(e.source);
    if (s && lid(s) === 'waf') wafOf.set(e.target, s.data.props);
  }
  const wafNode = services.find((n) => lid(n) === 'waf');

  const valueOf = (n: ServiceNode) => {
    const r = role(n);
    if (r === 'secrets') return 4;
    const cls = CLASS_VALUE[String(n.data.props.dataClass ?? 'Confidencial')] ?? 4;
    if (r === 'cache') return Math.min(cls, 3);
    return cls;
  };
  const isTarget = (n: ServiceNode) => DATA_ROLES.includes(role(n)) || role(n) === 'secrets';

  // Exposición directa en Security Groups manuales
  const openToInternet = (n: ServiceNode, port?: number) => {
    if (eff.mode !== 'manual') return false;
    return eff.sgIdsOf(n).some((gid) => eff.groups.find((g) => g.id === gid)?.inbound.some((r) => r.peer.kind === 'cidr' && isAnyCidr(r.peer.value) && (port === undefined || ruleCovers(r, port))));
  };

  /* ── controles reutilizables */
  const ctrl = (mitigation: string, label: string, ok: boolean, factor: number, fix?: AttackFix): AttackControl => ({ mitigation, label: tx(label), ok, factor, fix });
  const secCtrl = (key: string, mitigation: string, label: string, factor: number) => ctrl(mitigation, label, !!sec[key], factor, { label: `Activar: ${label}`, security: key });
  const wafCtrls = (w: Record<string, PropValue> | null, kind: 'web' | 'any'): AttackControl[] => {
    if (!w) return [ctrl('M1050', 'WAF delante del punto de entrada', false, 0.5)];
    const fixW = (props: Record<string, PropValue>, l: string): AttackFix | undefined => (wafNode ? { label: l, nodeId: wafNode.id, props } : undefined);
    return [
      ctrl('M1050', 'WAF con reglas administradas (OWASP)', !!w.managedRules, 0.5, fixW({ managedRules: true }, 'Activar reglas administradas del WAF')),
      ...(kind === 'web' ? [ctrl('M1050', 'Reglas de inyección SQL en el WAF', !!w.sqliRules, 0.7, fixW({ sqliRules: true }, 'Activar reglas SQLi del WAF'))] : []),
    ];
  };

  /* ── salto posible desde «from» (con el contexto del camino) hacia «to» */
  const likelihoodOf = (base: number, cs: AttackControl[]) => Math.max(0.01, cs.reduce((a, c) => a * (c.ok ? c.factor : 1), base));
  const step = (from: string, to: string, edgeIds: string[], tactic: Tactic, technique: Technique | null, how: string, base: number, controls: AttackControl[], virtual = false): AttackStep => ({ from, to, edgeIds, virtual, tactic, technique, how: tx(how), likelihood: likelihoodOf(base, controls), controls });

  interface Move {
    step: AttackStep;
    ctx: Ctx;
  }

  const movesFrom = (id: string, ctx: Ctx): Move[] => {
    const moves: Move[] = [];
    const n = svc(id);
    if (!n) return moves;
    const r = role(n);
    const nid = lid(n);

    // Con una cuenta robada: vuelve a entrar por la API como usuario legítimo
    if (r === 'identity' && ctx.mode === 'user') {
      for (const [entry, ids] of entryEdges) {
        const t = svc(entry);
        if (!t || role(t) === 'identity') continue;
        moves.push({ step: step(id, entry, ids, 'Acceso inicial', T.validAccounts, `Con las cuentas robadas obtiene tokens de ${n.data.label} y entra a ${t.data.label} como un usuario más.`, 1, []), ctx: { mode: 'user', waf: wafOf.get(entry) ?? null } });
      }
      return moves;
    }

    // Atravesar un punto de entrada (CDN, balanceador, API, DNS)
    if (ROUTERS.includes(r) && (ctx.mode === 'transit' || ctx.mode === 'user')) {
      for (const e of out.get(id) ?? []) {
        if (!allowed(e)) continue;
        const t = svc(e.target);
        if (!t) continue;
        const tr = role(t);
        const waf = wafOf.get(t.id) ?? ctx.waf;
        if (ROUTERS.includes(tr)) {
          moves.push({ step: step(id, t.id, [e.id], 'Acceso inicial', null, `Las peticiones maliciosas pasan por ${t.data.label} hacia el backend.`, 1, []), ctx: { mode: ctx.mode, waf } });
        } else if (tr === 'compute' && ctx.mode === 'transit') {
          const cs = [
            ...wafCtrls(waf, 'web'),
            secCtrl('inputValidation', 'M1048', 'Validación de entradas y consultas parametrizadas', 0.3),
            secCtrl('patching', 'M1051', 'Parcheo automático e Inspector', 0.6),
            secCtrl('sca', 'M1016', 'Escaneo de dependencias (SCA)', 0.75),
            secCtrl('sast', 'M1016', 'SAST/DAST en el pipeline', 0.8),
          ];
          moves.push({ step: step(id, t.id, [e.id], 'Acceso inicial', T.exploit, `Explota una vulnerabilidad de ${t.data.label} (inyección, deserialización, dependencia vulnerable) y ejecuta código con sus permisos.`, 0.6, cs), ctx: { mode: 'exec', waf } });
        } else if (tr === 'compute' && ctx.mode === 'user') {
          moves.push({ step: step(id, t.id, [e.id], 'Acceso inicial', null, `Con la sesión válida, ${n.data.label} le deja pasar hacia ${t.data.label} como a cualquier usuario.`, 1, []), ctx: { mode: 'user', waf } });
        } else if (tr === 'storage' && t.data.props.public) {
          moves.push({ step: step(id, t.id, [e.id], 'Recolección', T.cloudStorage, `Descarga los objetos de ${t.data.label}, que es público.`, 0.9, [ctrl('M1022', 'Bloqueo de acceso público en el bucket', false, 0.05, { label: 'Quitar el acceso público', nodeId: t.id, props: { public: false } })]), ctx: { mode: 'data', waf } });
        }
      }
      return moves;
    }

    if (r === 'compute' && (ctx.mode === 'exec' || ctx.mode === 'user')) {
      const asUser = ctx.mode === 'user';
      for (const e of out.get(id) ?? []) {
        if (!allowed(e)) continue;
        const t = svc(e.target);
        if (!t) continue;
        const tr = role(t);
        if (asUser) {
          if (tr === 'datastore' || tr === 'search' || (tr === 'storage' && !t.data.props.public)) {
            const cs = [secCtrl('objectAuthz', 'M1018', 'Autorización por objeto (BOLA)', 0.15), secCtrl('businessAudit', 'M1047', 'Auditoría de negocio', 0.85)];
            moves.push({ step: step(id, t.id, [e.id], 'Recolección', T.repo, `Cambia el identificador en las peticiones (IDOR/BOLA) y ${t.data.label} le devuelve datos de otros usuarios.`, 0.45, cs), ctx: { mode: 'data', waf: null } });
          }
          continue;
        }
        if (DATA_ROLES.includes(tr)) {
          const isCache = tr === 'cache';
          const cs: AttackControl[] = isCache
            ? [secCtrl('cacheAuth', 'M1026', 'AUTH token / RBAC en la caché', 0.4)]
            : [secCtrl('dataAuditLogs', 'M1047', 'Logs de acceso a los datos (detección)', 0.85)];
          moves.push({
            step: step(id, t.id, [e.id], 'Recolección', tr === 'storage' ? T.cloudStorage : T.repo, isCache ? `Lee las sesiones y tokens guardados en ${t.data.label} con la conexión de la app.` : `Usa la conexión y las credenciales de la app para consultar y volcar ${t.data.label}.`, 0.9, cs),
            ctx: { mode: 'data', waf: null },
          });
        } else if (tr === 'secrets') {
          moves.push({ step: step(id, t.id, [e.id], 'Acceso a credenciales', T.secretsStore, `Pide a ${t.data.label} los secretos que el rol de la app puede leer (contraseñas de BD, API keys).`, 0.9, [ctrl('M1027', 'Rotación automática de secretos', t.data.props.rotation !== false, 0.8)]), ctx: { mode: 'creds', waf: null } });
        } else if (tr === 'compute' && t.id !== id) {
          const cs = [secCtrl('serviceAuth', 'M1030', 'Autenticación entre servicios (mTLS / tokens)', 0.3), secCtrl('patching', 'M1051', 'Parcheo automático e Inspector', 0.6)];
          moves.push({ step: step(id, t.id, [e.id], 'Movimiento lateral', T.remoteExploit, `Desde ${n.data.label} llama a ${t.data.label}, que confía en la red interna, y lo compromete.`, 0.5, cs), ctx: { mode: 'exec', waf: null } });
        } else if (['queue', 'topic', 'eventbus', 'stream'].includes(tr)) {
          for (const e2 of out.get(t.id) ?? []) {
            const c2 = svc(e2.target);
            if (!c2 || role(c2) !== 'compute' || c2.id === id) continue;
            const cs = [secCtrl('schemaValidation', 'M1048', 'Validación del esquema de los mensajes', 0.3), secCtrl('resourcePolicies', 'M1018', 'Políticas de recurso en colas y tópicos', 0.8)];
            moves.push({ step: step(id, c2.id, [e.id, e2.id], 'Movimiento lateral', T.manipulation, `Publica mensajes manipulados en ${t.data.label}; ${c2.data.label} los procesa sin validarlos.`, 0.4, cs), ctx: { mode: 'exec', waf: null } });
          }
        }
      }
      // Abuso del rol IAM de la pieza: llega a lo que el rol permite, aunque no haya flecha
      const linked = new Set((out.get(id) ?? []).map((e) => e.target));
      for (const t of services) {
        if (t.id === id || linked.has(t.id)) continue;
        const tr = role(t);
        const tl = lid(t);
        const boundary = secCtrl('boundary', 'M1026', 'Permission boundary / roles de mínimo privilegio', 0.1);
        const scp = secCtrl('scp', 'M1054', 'Guardrails de la organización (SCP)', 0.7);
        if (tl === 'dynamodb' || tl === 's3' || tr === 'secrets') {
          moves.push({
            step: step(id, t.id, [], tr === 'secrets' ? 'Acceso a credenciales' : 'Escalada de privilegios', T.cloudAccounts, `Usa las credenciales temporales del rol de ${n.data.label} para llamar directo a la API de ${t.data.label}: no necesita una flecha en el diagrama, solo que el rol lo permita.`, 0.35, [boundary, scp], true),
            ctx: { mode: tr === 'secrets' ? 'creds' : 'data', waf: null },
          });
        } else if (['rds', 'aurora', 'documentdb', 'neptune', 'redshift'].includes(tl)) {
          moves.push({
            step: step(id, t.id, [], 'Exfiltración', T.transferAccount, `Con el rol de ${n.data.label} crea un snapshot de ${t.data.label} y lo comparte con su propia cuenta para leerlo con calma.`, 0.25, [boundary, scp, ctrl('M1041', 'Cifrado con llave propia (KMS) en la BD', t.data.props.encrypted !== false, 0.4)], true),
            ctx: { mode: 'data', waf: null },
          });
        }
      }
      return moves;
    }

    // Con secretos en la mano: entra a las bases de datos de la red
    if (ctx.mode === 'creds' && r === 'secrets') {
      for (const t of services) {
        if (!['rds', 'aurora', 'documentdb', 'redshift', 'neptune', 'opensearch'].includes(lid(t))) continue;
        moves.push({ step: step(id, t.id, [], 'Recolección', T.validAccounts, `Con la contraseña de la BD sacada de ${n.data.label} se conecta a ${t.data.label} desde la app comprometida.`, 0.85, [secCtrl('dataAuditLogs', 'M1047', 'Logs de acceso a los datos (detección)', 0.85), ctrl('M1027', 'Rotación automática de secretos', n.data.props.rotation !== false, 0.8)], true), ctx: { mode: 'data', waf: null } });
      }
    }
    return moves;
  };

  /* ── puntos de entrada desde Internet */
  const starts: Move[] = [];
  const entryEdges = new Map<string, string[]>();
  const entries = new Set<string>();
  const actors = services.filter((n) => ['actor', 'external'].includes(role(n)) && lid(n) !== 'onprem');
  const attacker = actors.find((n) => lid(n) === 'user') ?? actors[0];
  for (const a of actors) {
    for (const e of out.get(a.id) ?? []) {
      const t = svc(e.target);
      if (!t || !allowed(e)) continue;
      const hops: [AppEdge, ServiceNode][] = [];
      if (role(t) === 'dns') for (const e2 of out.get(t.id) ?? []) {
        const t2 = svc(e2.target);
        if (t2) hops.push([e2, t2]);
      }
      else hops.push([e, t]);
      for (const [e2, t2] of hops) {
        const edgeIds = e2 === e ? [e.id] : [e.id, e2.id];
        const tr = role(t2);
        entries.add(t2.id);
        if (!entryEdges.has(t2.id)) entryEdges.set(t2.id, edgeIds);
        if (ROUTERS.includes(tr)) {
          starts.push({ step: step(a.id, t2.id, edgeIds, 'Reconocimiento', T.scan, `Desde Internet escanea ${t2.data.label} buscando rutas, versiones y errores explotables.`, 1, []), ctx: { mode: 'transit', waf: wafOf.get(t2.id) ?? null } });
        } else if (tr === 'identity') {
          const cs = [
            ctrl('M1032', 'MFA obligatorio', String(t2.data.props.mfa ?? 'OPTIONAL') === 'ON', 0.1, { label: 'Hacer MFA obligatorio', nodeId: t2.id, props: { mfa: 'ON' } }),
            ctrl('M1036', 'Threat protection (credenciales filtradas, bloqueo adaptativo)', !!t2.data.props.threatProtection, 0.4, { label: 'Activar threat protection', nodeId: t2.id, props: { threatProtection: true } }),
            secCtrl('captcha', 'M1036', 'CAPTCHA en login y registro', 0.6),
          ];
          starts.push({ step: step(a.id, t2.id, edgeIds, 'Acceso a credenciales', T.stuffing, `Prueba millones de usuario/contraseña filtrados de otros sitios contra el login de ${t2.data.label} hasta entrar con cuentas reales.`, 0.5, cs), ctx: { mode: 'user', waf: null } });
        } else if (tr === 'compute') {
          const cs = [secCtrl('inputValidation', 'M1048', 'Validación de entradas y consultas parametrizadas', 0.3), secCtrl('patching', 'M1051', 'Parcheo automático e Inspector', 0.6), secCtrl('sca', 'M1016', 'Escaneo de dependencias (SCA)', 0.75)];
          starts.push({ step: step(a.id, t2.id, edgeIds, 'Acceso inicial', T.exploit, `${t2.data.label} recibe tráfico directo de Internet, sin WAF ni balanceador: explota una vulnerabilidad y ejecuta código.`, 0.6, [...wafCtrls(null, 'web'), ...cs]), ctx: { mode: 'exec', waf: null } });
        } else if (tr === 'storage' && t2.data.props.public) {
          starts.push({ step: step(a.id, t2.id, edgeIds, 'Recolección', T.cloudStorage, `${t2.data.label} es público: lo lista y descarga sin credenciales.`, 0.9, [ctrl('M1022', 'Bloqueo de acceso público en el bucket', false, 0.05, { label: 'Quitar el acceso público', nodeId: t2.id, props: { public: false } })]), ctx: { mode: 'data', waf: null } });
        }
      }
    }
  }
  const from0 = attacker?.id ?? 'internet';
  // Exposición sin flecha: buckets públicos, BD o SSH abiertos a 0.0.0.0/0
  for (const t of services) {
    const tr = role(t);
    if (tr === 'storage' && t.data.props.public && !starts.some((s) => s.step.to === t.id)) {
      entries.add(t.id);
      starts.push({ step: step(from0, t.id, [], 'Recolección', T.cloudStorage, `${t.data.label} es público: cualquiera que adivine el nombre del bucket lo lista y descarga.`, 0.8, [ctrl('M1022', 'Bloqueo de acceso público en el bucket', false, 0.05, { label: 'Quitar el acceso público', nodeId: t.id, props: { public: false } })], true), ctx: { mode: 'data', waf: null } });
    }
    if (['datastore', 'cache', 'search'].includes(tr) && openToInternet(t)) {
      entries.add(t.id);
      starts.push({ step: step(from0, t.id, [], 'Acceso inicial', T.brute, `Un Security Group abre ${t.data.label} a todo Internet: prueba contraseñas por defecto o filtradas directo contra el motor.`, 0.4, [secCtrl('dbTls', 'M1041', 'TLS obligatorio en la BD', 0.9)], true), ctx: { mode: 'data', waf: null } });
    }
    if (tr === 'compute' && (openToInternet(t, 22) || openToInternet(t, 3389))) {
      entries.add(t.id);
      starts.push({ step: step(from0, t.id, [], 'Acceso inicial', T.remote, `SSH/RDP abierto a Internet en ${t.data.label}: fuerza bruta o una llave filtrada le dan una consola.`, 0.3, [secCtrl('rootMfa', 'M1032', 'Acceso humano por SSO con MFA', 0.5), secCtrl('patching', 'M1051', 'Parcheo automático e Inspector', 0.7)], true), ctx: { mode: 'exec', waf: null } });
    }
  }

  /* ── búsqueda de caminos (DFS acotada) */
  const MAX_DEPTH = 7;
  const best = new Map<string, AttackStep[][]>();
  const keep = (target: string, steps: AttackStep[]) => {
    const list = best.get(target) ?? [];
    const lk = steps.reduce((a, s) => a * s.likelihood, 1);
    const sig = steps.map((s) => s.to).join('>');
    if (list.some((p) => p.map((s) => s.to).join('>') === sig)) return;
    list.push(steps);
    list.sort((a, b) => b.reduce((x, s) => x * s.likelihood, 1) - a.reduce((x, s) => x * s.likelihood, 1) || a.length - b.length);
    best.set(target, list.slice(0, 3));
    void lk;
  };
  const dfs = (id: string, ctx: Ctx, path: AttackStep[], seen: Set<string>) => {
    const lk = path.reduce((a, s) => a * s.likelihood, 1);
    if (lk < 0.002 || path.length >= MAX_DEPTH) return;
    for (const m of movesFrom(id, ctx)) {
      if (seen.has(m.step.to)) continue;
      const next = [...path, m.step];
      const t = svc(m.step.to);
      if (t && isTarget(t) && (m.ctx.mode === 'data' || m.ctx.mode === 'creds')) keep(t.id, next);
      if (m.ctx.mode === 'data') continue;
      seen.add(m.step.to);
      dfs(m.step.to, m.ctx, next, seen);
      seen.delete(m.step.to);
    }
  };
  for (const s of starts) {
    const t = svc(s.step.to);
    if (t && isTarget(t) && s.ctx.mode === 'data') keep(t.id, [s.step]);
    if (s.ctx.mode === 'data') continue;
    dfs(s.step.to, s.ctx, [s.step], new Set([s.step.from, s.step.to]));
  }

  /* ── rutas finales */
  const paths: AttackPath[] = [];
  for (const [target, list] of best) {
    const t = svc(target)!;
    const value = valueOf(t);
    list.slice(0, 2).forEach((steps, k) => {
      const likelihood = steps.reduce((a, s) => a * s.likelihood, 1);
      const score = likelihood * value;
      const risk: AttackPath['risk'] = score >= 1.2 ? 'Crítico' : score >= 0.4 ? 'Alto' : score >= 0.1 ? 'Medio' : 'Bajo';
      // El control faltante que más baja la ruta (cortar la cadena)
      let bestCut: AttackPath['bestCut'] = null;
      steps.forEach((s, i) => {
        for (const c of s.controls) {
          if (c.ok || !c.fix) continue;
          const after = (likelihood / s.likelihood) * Math.max(0.01, s.likelihood * c.factor);
          if (!bestCut || after < bestCut.after) bestCut = { step: i, control: c, after };
        }
      });
      paths.push({
        id: `${target}:${k}`,
        targetId: target,
        targetLabel: t.data.label,
        value,
        steps,
        likelihood,
        risk,
        title: `Así llegaría un atacante a «${t.data.label}» en ${steps.length} salto${steps.length > 1 ? 's' : ''}`,
        bestCut,
      });
    });
  }
  const rank = { Crítico: 4, Alto: 3, Medio: 2, Bajo: 1 };
  paths.sort((a, b) => rank[b.risk] - rank[a.risk] || b.likelihood * b.value - a.likelihood * a.value || a.steps.length - b.steps.length);
  const reached = new Set(paths.map((p) => p.targetId));
  const safeTargets = services.filter((n) => isTarget(n) && !reached.has(n.id)).map((n) => n.id);
  return { paths: paths.slice(0, 12), safeTargets, entries: [...entries] };
}

/** Para el lienzo: qué piezas y flechas recorre la ruta hasta el paso «upto». */
export function attackOverlay(p: AttackPath, upto: number) {
  const nodes = new Map<string, 'start' | 'hop' | 'target' | 'current'>();
  const edges = new Map<string, number>();
  const virtual: { id: string; source: string; target: string; step: number; label: string }[] = [];
  const steps = p.steps.slice(0, Math.max(0, upto));
  steps.forEach((s, i) => {
    if (i === 0) nodes.set(s.from, 'start');
    nodes.set(s.to, s.to === p.targetId ? 'target' : 'hop');
    if (s.edgeIds.length) for (const e of s.edgeIds) edges.set(e, i + 1);
    else virtual.push({ id: `atk-${i}`, source: s.from, target: s.to, step: i + 1, label: s.technique?.id ?? '' });
  });
  const cur = steps[steps.length - 1];
  if (cur) nodes.set(cur.to, cur.to === p.targetId ? 'target' : 'current');
  return { nodes, edges, virtual, labels: new Map(steps.map((s, i) => [s.edgeIds[s.edgeIds.length - 1] ?? `atk-${i}`, `${i + 1} · ${s.technique?.id ?? 'pasa'}`])) };
}
