/**
 * Simulación de una petición de usuario: sigue el camino real de un request por el
 * diagrama, salto a salto, revisando la configuración de red (SG, listeners, puertos,
 * rutas), el WAF y la autenticación. Si algo está mal configurado, dice dónde y por qué.
 */
import { getService, lid, primaryCloud } from '../catalog/catalog';
import { byId, isService } from '../lib/graph';
import { profileFor } from '../sim/profiles';
import type { AppEdge, AppNode, ConnData, SecurityGroup, ServiceNode } from '../types';
import { analyzeNetwork, type EdgeVerdict, type NetAnalysis, type NetCheck, type NetFix } from './reach';
import { inVpc, targetOf } from './model';

export type RequestKind = 'browse' | 'api' | 'api-noauth' | 'login' | 'sqli';

export interface RequestDef {
  id: RequestKind;
  label: string;
  method: string;
  path: string;
  /** Qué debería pasar en una arquitectura sana. */
  expect: 'success' | 'blocked';
  desc: string;
}

export const REQUESTS: RequestDef[] = [
  { id: 'browse', label: 'Abrir la web', method: 'GET', path: '/', expect: 'success', desc: 'Un usuario abre la página principal.' },
  { id: 'api', label: 'Llamar a la API (con sesión)', method: 'GET', path: '/api/pedidos', expect: 'success', desc: 'Petición autenticada con un token válido: debe llegar a los datos y responder 200.' },
  { id: 'login', label: 'Iniciar sesión', method: 'POST', path: '/login', expect: 'success', desc: 'El usuario se autentica y recibe un token.' },
  { id: 'api-noauth', label: 'API sin token', method: 'GET', path: '/api/pedidos', expect: 'blocked', desc: 'Alguien llama a la API sin iniciar sesión: debería recibir 401.' },
  { id: 'sqli', label: 'Ataque: inyección SQL', method: 'GET', path: "/api/pedidos?id=1' OR '1'='1", expect: 'blocked', desc: 'Un atacante intenta una inyección SQL: el WAF debería frenarla (403).' },
];

export type HopStatus = 'ok' | 'fail' | 'blocked' | 'warn' | 'info';

export interface TraceHop {
  id: string;
  nodeId: string;
  edgeId?: string;
  fromId?: string;
  title: string;
  detail: string;
  status: HopStatus;
  /** ms acumulados al llegar aquí. */
  at: number;
  depth: number;
  async?: boolean;
  checks: NetCheck[];
}

export type Outcome = 'ok' | 'error' | 'blocked' | 'insecure' | 'partial' | 'na';

export interface TraceResult {
  request: RequestDef;
  entryId: string | null;
  targetId: string | null;
  hops: TraceHop[];
  /** 0 = no hubo respuesta HTTP (timeout / rechazo en el navegador). */
  status: number;
  statusText: string;
  totalMs: number;
  outcome: Outcome;
  /** ¿El resultado es el que se espera de una arquitectura sana? */
  asExpected: boolean;
  headline: string;
  /** Explicación de dónde se equivocó el arquitecto (vacío si todo va bien). */
  problems: { nodeId: string; edgeId?: string; title: string; detail: string; fix?: NetFix }[];
  notes: string[];
  nodeIds: string[];
  edgeIds: string[];
  failedEdgeId?: string;
  failedNodeId?: string;
}

const ROUTERS = ['actor', 'external', 'dns', 'cdn', 'lb', 'api', 'inspection'];
const LEAVES = ['datastore', 'cache', 'search', 'storage', 'secrets', 'identity', 'external', 'ai'];
const ASYNC = ['queue', 'topic', 'stream', 'eventbus'];
const IGNORE = ['observability', 'kms', 'cert', 'devops', 'analytics', 'netgw', 'waf', 'registry'];

const TIMEOUT: Record<string, number> = { actor: 21000, external: 21000, dns: 21000, cdn: 30000, lb: 10000, api: 29000, compute: 10000, workflow: 10000 };

export function traceRequest(
  nodes: AppNode[],
  edges: AppEdge[],
  groups: SecurityGroup[] | undefined,
  opts: { kind: RequestKind; entryId?: string | null; targetId?: string | null },
  analysis?: NetAnalysis,
): TraceResult {
  const request = REQUESTS.find((r) => r.id === opts.kind) ?? REQUESTS[0];
  const map = byId(nodes);
  const net = analysis ?? analyzeNetwork(nodes, edges, groups);
  const azure = primaryCloud(nodes) === 'azure';
  const services = nodes.filter(isService);
  const role = (n: ServiceNode) => getService(n.data.serviceId).role;
  const svc = (id: string) => {
    const n = map.get(id);
    return isService(n) ? n : undefined;
  };
  const isAsyncEdge = (e: AppEdge) => !!(e.data as ConnData | undefined)?.async;
  const outEdges = (id: string) =>
    edges.filter((e) => {
      if (e.source !== id) return false;
      const t = svc(e.target);
      return !!t && !IGNORE.includes(role(t)) && role(t) !== 'actor';
    });
  const protectorsOf = (id: string) => edges.filter((e) => e.target === id).map((e) => svc(e.source)).filter((n): n is ServiceNode => !!n && role(n) === 'waf');
  const procMs = (n: ServiceNode) => {
    try {
      const l = profileFor(n).latency;
      return Number.isFinite(l) ? Math.min(l, 400) : 5;
    } catch {
      return 5;
    }
  };
  const wire = (from: ServiceNode | undefined, to: ServiceNode) => {
    if (!from) return 0;
    const rf = role(from);
    if (['actor', 'external'].includes(rf)) return 25;
    if (inVpc(from, map) && inVpc(to, map)) return 1;
    if (rf === 'cdn') return 12;
    return 4;
  };

  const result: TraceResult = {
    request,
    entryId: null,
    targetId: opts.targetId ?? null,
    hops: [],
    status: 0,
    statusText: '',
    totalMs: 0,
    outcome: 'ok',
    asExpected: true,
    headline: '',
    problems: [],
    notes: [],
    nodeIds: [],
    edgeIds: [],
  };

  // ── Punto de partida
  const entry = (opts.entryId && svc(opts.entryId)) || services.find((n) => role(n) === 'actor') || services.find((n) => role(n) === 'external');
  if (!entry) {
    result.outcome = 'error';
    result.asExpected = false;
    result.headline = 'Agrega una pieza «Usuario» conectada a la entrada de tu arquitectura (CDN, balanceador o API) para simular peticiones.';
    return result;
  }
  result.entryId = entry.id;

  // ── Alcanzabilidad (para elegir la rama hacia un destino concreto)
  const reach = new Map<string, Set<string>>();
  const reachable = (id: string): Set<string> => {
    if (reach.has(id)) return reach.get(id)!;
    const seen = new Set<string>();
    const stack = [id];
    while (stack.length) {
      const cur = stack.pop()!;
      for (const e of outEdges(cur)) {
        if (seen.has(e.target)) continue;
        seen.add(e.target);
        const t = svc(e.target)!;
        if (!ASYNC.includes(role(t))) stack.push(e.target);
      }
    }
    reach.set(id, seen);
    return seen;
  };
  const target = opts.targetId ? svc(opts.targetId) : undefined;

  const wantsStatic = request.id === 'browse';
  const rank = (n: ServiceNode, from: ServiceNode): number => {
    if (target && (n.id === target.id || reachable(n.id).has(target.id))) return -100;
    const r: string = role(n);
    if (role(from) === 'cdn' || role(from) === 'actor' || role(from) === 'dns') {
      if (wantsStatic) return ({ cdn: 0, storage: 1, lb: 2, api: 3, compute: 4 } as Record<string, number>)[r] ?? 9;
      return ({ api: 0, cdn: 1, lb: 2, compute: 3, storage: 8 } as Record<string, number>)[r] ?? 9;
    }
    return ({ compute: 0, workflow: 1, lb: 2, api: 3 } as Record<string, number>)[r] ?? 9;
  };

  let clock = 0;
  let failed = false;
  let blocked = false;
  let authSeen = false;
  let sqliReachedDb: ServiceNode | null = null;
  let firstConnect = true;
  const visited = new Set<string>();
  const asyncFailures: string[] = [];

  const push = (h: Omit<TraceHop, 'id'>) => {
    const hop = { ...h, id: `h${result.hops.length}` };
    result.hops.push(hop);
    if (!result.nodeIds.includes(h.nodeId)) result.nodeIds.push(h.nodeId);
    if (h.edgeId && !result.edgeIds.includes(h.edgeId)) result.edgeIds.push(h.edgeId);
    return hop;
  };

  const failureStatus = (c: NetCheck, from: ServiceNode, first: boolean): [number, string] => {
    const rf = role(from);
    const proxied = ['cdn', 'lb', 'api'].includes(rf);
    const app = ['compute', 'workflow'].includes(rf);
    const refused = c.id === 'listener' || c.id === 'redirect';
    if (c.id === 'redirect-loop') return [0, 'ERR_TOO_MANY_REDIRECTS'];
    if (c.id === 'cert') return first ? [0, 'ERR_SSL_PROTOCOL_ERROR'] : [502, 'Bad Gateway'];
    if (c.id === 'tg-port') return [503, 'Service Unavailable (sin targets sanos)'];
    if (first && !proxied) return refused ? [0, 'ERR_CONNECTION_REFUSED'] : [0, 'ERR_CONNECTION_TIMED_OUT'];
    if (proxied) return refused ? [502, 'Bad Gateway'] : [504, 'Gateway Timeout'];
    if (app) return [500, 'Internal Server Error'];
    return [502, 'Bad Gateway'];
  };

  const describeEdge = (from: ServiceNode, to: ServiceNode, v?: EdgeVerdict) => {
    const port = v && v.port ? ` :${v.port}` : '';
    const name = role(from) === 'dns' ? `${entry!.data.label} (vía ${from.data.label})` : from.data.label;
    return `${name} → ${to.data.label}${port}`;
  };

  /** Recorre la conexión from → to. Devuelve false si la petición murió ahí. */
  const hopTo = (from: ServiceNode | undefined, to: ServiceNode, e: AppEdge | undefined, depth: number, isAsync: boolean, verb: string): boolean => {
    const v = e ? net.verdicts.get(e.id) : undefined;
    const errs = v ? v.checks.filter((c) => !c.ok && c.severity === 'error') : [];
    const warns = v ? v.checks.filter((c) => !c.ok && c.severity === 'warn') : [];
    const isClient = !!from && ['actor', 'external'].includes(role(from));
    const first = isClient || (!!from && role(from) === 'dns' && firstConnect);
    if (v && v.kind !== 'none' && v.kind !== 'managed' && first) firstConnect = false;
    if (errs.length && from) {
      const c = errs[0];
      const [code, text] = failureStatus(c, from, first);
      const waited = c.id === 'listener' || c.id === 'cert' || c.id === 'tg-port' || c.id === 'redirect-loop' ? 5 : TIMEOUT[role(from)] ?? 10000;
      clock += waited;
      push({
        nodeId: to.id,
        edgeId: e?.id,
        fromId: from.id,
        title: describeEdge(from, to, v),
        detail: `${c.title}. ${c.detail}${waited > 1000 ? ` (esperó ${Math.round(waited / 1000)} s)` : ''}`,
        status: 'fail',
        at: clock,
        depth,
        async: isAsync,
        checks: v!.checks,
      });
      for (const x of errs) result.problems.push({ nodeId: to.id, edgeId: e?.id, title: x.title, detail: x.detail, fix: x.fix });
      if (isAsync) {
        asyncFailures.push(`${from.data.label} → ${to.data.label}`);
        return false;
      }
      failed = true;
      result.failedEdgeId = e?.id;
      result.failedNodeId = to.id;
      if (!result.statusText) {
        result.status = code;
        result.statusText = text;
      }
      return false;
    }
    clock += wire(from, to);
    const okLine = v && v.kind === 'connect' ? v.summary : v && v.kind === 'egress' ? v.summary : '';
    push({
      nodeId: to.id,
      edgeId: e?.id,
      fromId: from?.id,
      title: from ? describeEdge(from, to, v) : to.data.label,
      detail: [verb, okLine].filter(Boolean).join(' · '),
      status: warns.length ? 'warn' : 'ok',
      at: clock,
      depth,
      async: isAsync,
      checks: v?.checks ?? [],
    });
    clock += procMs(to);
    return true;
  };

  /** Controles en la puerta de una pieza de borde: WAF y autenticación. */
  const gate = (n: ServiceNode, depth: number): boolean => {
    const r = role(n);
    if (r === 'inspection') {
      // Firewall virtual detrás del GWLB: ¿ve el contenido y bloquea?
      const fleet: ServiceNode[] = [];
      const stack = [n.id];
      const seenI = new Set(stack);
      while (stack.length) {
        const cur = stack.pop()!;
        for (const e of outEdges(cur)) {
          const x = svc(e.target);
          if (!x) continue;
          if (role(x) === 'appliance') fleet.push(x);
          else if (role(x) === 'inspection' && !seenI.has(x.id)) {
            seenI.add(x.id);
            stack.push(x.id);
          }
        }
      }
      const fw = fleet[0];
      if (!fw) return true;
      const fp = fw.data.props;
      const clear = result.hops.some((h) => ['lb', 'api'].includes(role(svc(h.nodeId) ?? fw))) || !!fp.tlsDecryption;
      const ips = !String(fp.mode ?? 'IPS').startsWith('IDS') && fp.threatPrevention !== false;
      clock += fp.tlsDecryption ? 6 : 2;
      if (request.id === 'sqli' && clear && ips) {
        push({ nodeId: fw.id, fromId: n.id, title: `${fw.data.label} (vía ${n.data.label})`, detail: 'El IPS reconoce la firma del exploit en el contenido y descarta la conexión.', status: 'blocked', at: clock, depth, checks: [] });
        blocked = true;
        result.status = 0;
        result.statusText = 'ERR_CONNECTION_RESET (IPS)';
        return false;
      }
      push({
        nodeId: fw.id,
        fromId: n.id,
        title: `${fw.data.label} (vía ${n.data.label})`,
        detail: !clear ? 'Inspecciona solo IPs, puertos y SNI: el contenido viaja cifrado (TLS) y el firewall no lo descifra.' : request.id === 'sqli' ? (ips ? 'Inspecciona el contenido.' : 'Modo IDS: genera una alerta pero deja pasar la petición.') : 'Inspecciona la petición y la deja pasar.',
        status: !clear && request.id === 'sqli' ? 'warn' : request.id === 'sqli' && !ips ? 'warn' : 'ok',
        at: clock,
        depth,
        checks: [],
      });
      return true;
    }
    if (!['cdn', 'lb', 'api'].includes(r)) return true;
    const wafs = protectorsOf(n.id).filter((w) => lid(w) === 'waf');
    const waf = wafs[0];
    if (request.id === 'sqli') {
      if (waf && waf.data.props.sqliRules !== false) {
        clock += 1;
        push({ nodeId: waf.id, fromId: n.id, title: `${waf.data.label} en ${n.data.label}`, detail: `La regla de inyección SQL detecta «' OR '1'='1» y bloquea la petición.`, status: 'blocked', at: clock, depth, checks: [] });
        blocked = true;
        result.status = 403;
        result.statusText = 'Forbidden (WAF)';
        return false;
      }
      if (waf) {
        push({ nodeId: waf.id, fromId: n.id, title: `${waf.data.label} en ${n.data.label}`, detail: 'El WAF no tiene activas las reglas de inyección SQL: deja pasar el payload.', status: 'warn', at: clock, depth, checks: [] });
        result.problems.push({ nodeId: waf.id, title: `${waf.data.label}: reglas de inyección SQL desactivadas`, detail: 'Activa el grupo de reglas SQLi del WAF.', fix: { kind: 'service', fix: { label: 'Activar reglas SQLi', setProps: [{ nodeId: waf.id, props: { sqliRules: true } }] }, label: 'Activar reglas SQLi' } });
      }
    } else if (waf) {
      push({ nodeId: waf.id, fromId: n.id, title: `${waf.data.label} en ${n.data.label}`, detail: 'Petición legítima: ninguna regla coincide, pasa.', status: 'ok', at: clock, depth, checks: [] });
    }
    // Autenticación en el borde (autorizador JWT de API Gateway / authenticate-oidc del ALB)
    const authEdge = request.id !== 'browse' && request.id !== 'login' ? edges.find((e) => e.source === n.id && svc(e.target) && role(svc(e.target)!) === 'identity') : undefined;
    if (authEdge) {
      const idp = svc(authEdge.target)!;
      authSeen = true;
      if (request.id === 'api-noauth') {
        clock += 3;
        push({ nodeId: idp.id, edgeId: authEdge.id, fromId: n.id, title: `${n.data.label}: autorizador (${idp.data.label})`, detail: 'La petición no trae token (Authorization ausente): se rechaza antes de llegar al backend.', status: 'blocked', at: clock, depth, checks: [] });
        blocked = true;
        result.status = 401;
        result.statusText = 'Unauthorized';
        return false;
      }
      clock += 2;
      push({ nodeId: idp.id, edgeId: authEdge.id, fromId: n.id, title: `${n.data.label}: autorizador (${idp.data.label})`, detail: 'Token JWT válido (firma verificada con las llaves públicas en caché).', status: 'ok', at: clock, depth, checks: [] });
    }
    return true;
  };

  /** El código de la aplicación: llama a sus dependencias. */
  const fanOut = (n: ServiceNode, depth: number, isAsync: boolean): boolean => {
    const outs = outEdges(n.id).filter((e) => !visited.has(`${n.id}>${e.target}`));
    // La app valida el token si está conectada al proveedor de identidad
    const idpEdge = outs.find((e) => role(svc(e.target)!) === 'identity');
    if (idpEdge && !isAsync && request.id !== 'browse') {
      const idp = svc(idpEdge.target)!;
      visited.add(`${n.id}>${idp.id}`);
      if (request.id === 'api-noauth' && !authSeen) {
        authSeen = true;
        push({ nodeId: idp.id, edgeId: idpEdge.id, fromId: n.id, title: `${n.data.label} valida el token`, detail: 'No hay token: la aplicación responde 401.', status: 'blocked', at: clock, depth, checks: [] });
        blocked = true;
        result.status = 401;
        result.statusText = 'Unauthorized';
        return false;
      }
      if (request.id === 'login') {
        if (!hopTo(n, idp, idpEdge, depth, isAsync, 'Autentica las credenciales y obtiene el token')) return false;
      } else if (!authSeen) {
        authSeen = true;
        push({ nodeId: idp.id, edgeId: idpEdge.id, fromId: n.id, title: `${n.data.label} valida el token`, detail: `Firma del JWT verificada con las llaves de ${idp.data.label} (en caché).`, status: 'ok', at: clock, depth, checks: [] });
      }
    }
    const order = (e: AppEdge) => {
      const r = role(svc(e.target)!);
      return r === 'secrets' ? 0 : r === 'cache' ? 1 : r === 'datastore' || r === 'search' ? 2 : r === 'storage' ? 3 : ASYNC.includes(r) ? 6 : 4;
    };
    for (const e of [...outs].sort((a, b) => order(a) - order(b))) {
      const t = svc(e.target)!;
      const r = role(t);
      if (r === 'identity') continue;
      visited.add(`${n.id}>${t.id}`);
      if (ASYNC.includes(r) || (isAsyncEdge(e) && !LEAVES.includes(r))) {
        if (isAsync && depth > 6) continue;
        const ok = hopTo(n, t, e, depth, isAsync, ASYNC.includes(r) ? 'Publica un mensaje (asíncrono)' : 'Invocación asíncrona');
        if (!ok) {
          if (isAsync) continue;
          return false;
        }
        consumeAsync(t, depth + 1);
        continue;
      }
      if (LEAVES.includes(r)) {
        const verb =
          r === 'datastore' ? (request.id === 'sqli' ? 'Ejecuta la consulta con el parámetro del usuario' : 'Consulta la base de datos')
          : r === 'cache' ? 'Busca en caché'
          : r === 'search' ? 'Consulta el índice'
          : r === 'storage' ? 'Lee/escribe un objeto'
          : r === 'secrets' ? 'Obtiene credenciales (al arrancar; luego en caché)'
          : r === 'ai' ? 'Invoca el modelo'
          : 'Llama a la API externa';
        if (!hopTo(n, t, e, depth, isAsync, verb)) {
          if (isAsync) return false;
          return false;
        }
        if (request.id === 'sqli' && r === 'datastore' && !isAsync) sqliReachedDb = t;
        continue;
      }
      // Llamada a otro servicio (microservicio, balanceador interno, función…)
      if (['compute', 'workflow', 'lb', 'api'].includes(r)) {
        if (!hopTo(n, t, e, depth, isAsync, 'Llama a otro servicio')) return false;
        if (!walk(t, depth + 1, isAsync)) return false;
      }
    }
    return true;
  };

  const consumeAsync = (q: ServiceNode, depth: number) => {
    for (const e of outEdges(q.id)) {
      const c = svc(e.target)!;
      if (!['compute', 'workflow'].includes(role(c)) || visited.has(`${q.id}>${c.id}`)) continue;
      visited.add(`${q.id}>${c.id}`);
      if (!hopTo(q, c, e, depth, true, `${c.data.label} procesa el mensaje`)) continue;
      walk(c, depth + 1, true);
    }
  };

  /** Avanza desde una pieza: routers eligen un camino; el cómputo llama a sus dependencias. */
  const walk = (n: ServiceNode, depth: number, isAsync: boolean): boolean => {
    if (depth > 14) return true;
    const r = role(n);
    if (!gate(n, depth)) return false;
    if (['compute', 'workflow'].includes(r)) return fanOut(n, depth, isAsync);
    if (!ROUTERS.includes(r)) return true;
    const outs = outEdges(n.id).filter((e) => {
      const t = svc(e.target)!;
      const rt = role(t);
      return rt !== 'identity' && rt !== 'dns' && rt !== 'appliance' && !(r === 'inspection' && rt === 'inspection') && !ASYNC.includes(rt) && !visited.has(`${n.id}>${t.id}`);
    });
    if (!outs.length) {
      if (r === 'cdn' || r === 'lb' || r === 'api') {
        push({ nodeId: n.id, title: `${n.data.label} no tiene destino`, detail: 'No hay ninguna flecha hacia un origen / target: responde error.', status: 'fail', at: clock, depth, checks: [] });
        result.problems.push({ nodeId: n.id, title: `${n.data.label} no tiene a dónde enviar la petición`, detail: 'Conéctalo a la aplicación (o al bucket de estáticos).' });
        failed = true;
        result.failedNodeId = n.id;
        result.status = r === 'lb' ? 503 : 502;
        result.statusText = r === 'lb' ? 'Service Unavailable' : 'Bad Gateway';
        return false;
      }
      return true;
    }
    const next = [...outs].sort((a, b) => rank(svc(a.target)!, n) - rank(svc(b.target)!, n))[0];
    const t = svc(next.target)!;
    visited.add(`${n.id}>${t.id}`);
    let verb = 'Reenvía la petición';
    if (r === 'cdn') verb = role(t) === 'storage' ? (wantsStatic ? 'Sirve el HTML/JS desde caché o el origen de estáticos' : 'Origen de estáticos') : `Reenvía al origen (${n.data.net?.originProtocol === 'http-only' ? 'HTTP' : 'HTTPS'})`;
    if (r === 'lb') {
      const tg = targetOf(n, t);
      verb = `Target group ${tg.protocol} ${tg.port} → target sano`;
    }
    if (r === 'api') verb = 'Integración con el backend';
    if (!hopTo(n, t, next, depth, isAsync, verb)) return false;
    return walk(t, depth + (['compute', 'workflow'].includes(role(t)) ? 1 : 0), isAsync);
  };

  // ── Inicio: DNS + primer salto
  push({ nodeId: entry.id, title: `${entry.data.label}: ${request.method} ${request.path}`, detail: request.desc, status: 'info', at: 0, depth: 0, checks: [] });

  if (request.id === 'login') {
    const idpEdge = outEdges(entry.id).find((e) => role(svc(e.target)!) === 'identity');
    if (idpEdge) {
      const idp = svc(idpEdge.target)!;
      if (hopTo(entry, idp, idpEdge, 0, false, `Login en ${idp.data.label} (OIDC): valida usuario${idp.data.props.mfa === 'ON' ? ' + MFA' : ''} y emite tokens`)) {
        result.status = 200;
        result.statusText = 'OK (token emitido)';
      }
      return finish();
    }
    const anyIdp = services.find((x) => role(x) === 'identity');
    result.notes.push(anyIdp ? `El usuario no tiene flecha hacia ${anyIdp.data.label}: se asume que el login pasa por la API.` : 'No hay proveedor de identidad en el diagrama: el login lo implementa la aplicación (guarda contraseñas y emite sesiones).');
  }

  const dnsEdge = outEdges(entry.id).find((e) => role(svc(e.target)!) === 'dns');
  let start: ServiceNode = entry;
  let startEdges = outEdges(entry.id).filter((e) => !['dns', 'identity'].includes(role(svc(e.target)!)));
  if (dnsEdge) {
    const dns = svc(dnsEdge.target)!;
    clock += 20;
    const resolved = outEdges(dns.id).filter((e) => ['cdn', 'lb', 'api', 'compute'].includes(role(svc(e.target)!)));
    push({ nodeId: dns.id, edgeId: dnsEdge.id, fromId: entry.id, title: `Resolución DNS (${dns.data.label})`, detail: resolved.length ? `El nombre resuelve a ${resolved.map((e) => svc(e.target)!.data.label).join(' / ')}.` : 'El registro no apunta a ninguna pieza.', status: resolved.length || startEdges.length ? 'ok' : 'warn', at: clock, depth: 0, checks: [] });
    // Si el usuario no tiene flecha directa, la conexión sale "desde Internet" usando la flecha DNS → destino.
    if (!startEdges.length && resolved.length) {
      start = dns;
      startEdges = resolved;
    }
  }
  if (!startEdges.length) {
    result.outcome = 'na';
    result.asExpected = true;
    result.headline = `${entry.data.label} no está conectado a una entrada web (CDN, balanceador o API): no hay petición HTTP que simular. Si es un error, conecta el usuario (o el DNS) con la entrada.`;
    return result;
  }
  {
    const next = [...startEdges].sort((a, b) => rank(svc(a.target)!, entry) - rank(svc(b.target)!, entry))[0];
    const t = svc(next.target)!;
    visited.add(`${start.id}>${t.id}`);
    const ok = hopTo(start, t, next, 0, false, role(t) === 'cdn' ? 'Conexión HTTPS al borde más cercano' : role(t) === 'lb' ? 'Conexión al balanceador' : 'Conexión');
    if (ok) walk(t, ['compute', 'workflow'].includes(role(t)) ? 1 : 0, false);
  }
  return finish();

  function finish(): TraceResult {
    result.totalMs = Math.round(clock);
    if (failed) {
      result.outcome = 'error';
    } else if (blocked) {
      result.outcome = 'blocked';
    } else {
      const loginDone = result.status === 200;
      if (!result.status) {
        result.status = 200;
        result.statusText = 'OK';
      }
      result.outcome = 'ok';
      const reachedBackend = result.hops.some((h) => {
        const n = svc(h.nodeId);
        return !!n && ['compute', 'workflow', 'api'].includes(role(n));
      });
      if (request.id !== 'browse' && !reachedBackend && !loginDone) {
        result.outcome = 'na';
        result.asExpected = true;
        result.status = 404;
        result.statusText = 'Not Found';
        result.notes.push('La petición terminó en el origen de estáticos: esta arquitectura no tiene backend que la atienda.');
        result.headline = `No aplica: la arquitectura no tiene API (la ruta ${request.path.split('?')[0]} la responde el origen de estáticos con 404).`;
        return result;
      }
      if (request.id === 'sqli') {
        result.outcome = 'insecure';
        const waf = services.find((x) => lid(x) === 'waf');
        const at = sqliReachedDb ? (sqliReachedDb as ServiceNode).data.label : 'la aplicación';
        result.problems.push({
          nodeId: sqliReachedDb ? (sqliReachedDb as ServiceNode).id : result.hops[result.hops.length - 1].nodeId,
          title: `La inyección SQL llegó hasta ${at}`,
          detail: `${waf ? 'Hay WAF pero no protege esta entrada o no tiene reglas SQLi.' : 'No hay WAF delante de la entrada.'} La única defensa que queda es el código (consultas parametrizadas).`,
          fix: waf ? undefined : { kind: 'service', fix: { label: 'Agregar WAF', add: [{ serviceId: 'waf', parent: null }], connect: [{ source: 'new:0', target: result.hops.map((h) => svc(h.nodeId)).find((n) => !!n && ['cdn', 'lb', 'api'].includes(role(n)))?.id ?? '' }].filter((c) => c.target) }, label: 'Agregar WAF en la entrada' },
        });
      }
      if (request.id === 'api-noauth') {
        result.outcome = 'insecure';
        const front = result.hops.map((h) => svc(h.nodeId)).find((n): n is ServiceNode => !!n && ['api', 'lb'].includes(role(n)));
        const app = result.hops.map((h) => svc(h.nodeId)).find((n): n is ServiceNode => !!n && ['compute', 'workflow'].includes(role(n)));
        const host = front && role(front) === 'api' ? front : app ?? front;
        const idp = services.find((x) => role(x) === 'identity');
        result.problems.push({
          nodeId: host?.id ?? result.hops[result.hops.length - 1].nodeId,
          title: 'La API respondió sin pedir token',
          detail: `Ninguna pieza del camino valida la identidad. Conecta ${host ? host.data.label : 'la entrada'} con ${idp ? idp.data.label : 'un proveedor de identidad'} (autorizador JWT / validación del token en la app).`,
          fix: host ? { kind: 'service', fix: idp ? { label: `Validar token con ${idp.data.label}`, connect: [{ source: host.id, target: idp.id }] } : { label: 'Agregar proveedor de identidad', add: [{ serviceId: 'cognito' }], connect: [{ source: host.id, target: 'new:0' }] }, label: idp ? `Conectar ${host.data.label} → ${idp.data.label}` : `Agregar ${azure ? 'Entra External ID' : 'Cognito'}` } : undefined,
        });
      }
      if (asyncFailures.length && result.outcome === 'ok') result.outcome = 'partial';
    }
    result.asExpected = request.expect === 'success' ? result.outcome === 'ok' : result.outcome === 'blocked';
    const code = result.status ? `${result.status} ${result.statusText}` : result.statusText;
    const where = result.failedEdgeId ? (() => {
      const e = edges.find((x) => x.id === result.failedEdgeId);
      const a = e && svc(e.source);
      const b = e && svc(e.target);
      return a && b ? ` entre ${a.data.label} y ${b.data.label}` : '';
    })() : result.failedNodeId ? ` en ${svc(result.failedNodeId)?.data.label ?? ''}` : '';
    result.headline =
      result.outcome === 'ok' ? `✓ ${code} en ${result.totalMs} ms — la petición recorrió ${result.nodeIds.length} piezas sin problemas.`
      : result.outcome === 'partial' ? `${code} para el usuario, pero el procesamiento asíncrono falla (${asyncFailures.join(', ')}).`
      : result.outcome === 'blocked' ? `✓ ${code}: ${request.id === 'sqli' ? 'el ataque se frenó en el borde' : 'la petición sin credenciales fue rechazada'}, como debe ser.`
      : result.outcome === 'insecure' ? `⚠ ${code}: ${request.id === 'sqli' ? 'el ataque NO fue bloqueado' : 'la API respondió sin autenticación'}.`
      : `✗ ${code} — la petición falló${where}.`;
    return result;
  }
}

/** Helper para la UI: estado por pieza / flecha del trazado (para pintar el lienzo). */
export function traceOverlay(r: TraceResult) {
  const nodes = new Map<string, HopStatus>();
  const edges = new Map<string, HopStatus>();
  const sev: Record<HopStatus, number> = { info: 0, ok: 1, warn: 2, blocked: 3, fail: 4 };
  for (const h of r.hops) {
    const cur = nodes.get(h.nodeId);
    if (!cur || sev[h.status] > sev[cur]) nodes.set(h.nodeId, h.status);
    if (h.edgeId) {
      const ce = edges.get(h.edgeId);
      if (!ce || sev[h.status] > sev[ce]) edges.set(h.edgeId, h.status);
    }
  }
  return { nodes, edges };
}

