/**
 * Análisis de alcanzabilidad: ¿cada flecha del diagrama puede conectarse de verdad
 * con la configuración de red actual (SG, listeners, puertos, rutas de salida)?
 */
import { getService, lid, primaryCloud } from '../catalog/catalog';
import { byId, isService, isZone, placementOf } from '../lib/graph';
import type { AppEdge, AppNode, ConnData, Listener, NetFix, SecurityGroup, ServiceNode, SgRule } from '../types';
import {
  cidrContains,
  cidrOf,
  effectiveNet,
  generateSecurityGroups,
  inVpc,
  isAnyCidr,
  isLb,
  listenersOf,
  listenPort,
  needsSg,
  originProtocol,
  peerIs,
  ruleCovers,
  ruleText,
  semantics,
  targetOf,
  type ConnKind,
  type EffectiveNet,
} from './model';

export type { NetFix };

export interface NetCheck {
  id: string;
  ok: boolean;
  severity: 'error' | 'warn';
  title: string;
  detail: string;
  fix?: NetFix;
  /** Piezas afectadas (para los chequeos generales). */
  nodeIds?: string[];
}

export interface EdgeVerdict {
  edgeId: string;
  kind: ConnKind;
  fromId: string;
  toId: string;
  port: number;
  ok: boolean;
  checks: NetCheck[];
  /** Frase corta del primer problema (o del camino correcto). */
  summary: string;
  /** Código HTTP / efecto que vería quien llama si falla. */
  failure?: string;
  /** Etiqueta corta para el lienzo (p. ej. «SG bloquea :8080»). */
  short?: string;
}

export interface NetAnalysis {
  mode: 'auto' | 'manual';
  net: EffectiveNet;
  verdicts: Map<string, EdgeVerdict>;
  /** Problemas que no son de una flecha concreta (SG demasiado abiertos, ASG mal dimensionado…). */
  general: NetCheck[];
}

const ENDPOINT_FOR: Record<string, string[]> = {
  s3: ['s3', 'blob'],
  dynamodb: ['dynamodb', 'Sql (Cosmos)'],
  sqs: ['sqs', 'namespace (Service Bus)'],
  secrets: ['secretsmanager', 'vault'],
  cloudwatch: ['logs'],
  ecr: ['ecr.api', 'registry'],
  rds: ['sqlServer'],
};

export function analyzeNetwork(nodes: AppNode[], edges: AppEdge[], groups?: SecurityGroup[]): NetAnalysis {
  const map = byId(nodes);
  const net = effectiveNet(nodes, edges, groups);
  const services = nodes.filter(isService);
  const azure = primaryCloud(nodes) === 'azure';
  const SG = azure ? 'NSG' : 'SG';
  const CDN = azure ? 'Front Door' : 'CloudFront';
  const gById = new Map(net.groups.map((g) => [g.id, g]));
  const sgsOf = (n: ServiceNode) => net.sgIdsOf(n).map((id) => gById.get(id)).filter((g): g is SecurityGroup => !!g);
  const verdicts = new Map<string, EdgeVerdict>();
  const role = (n: ServiceNode) => getService(n.data.serviceId).role;
  const vpcOf = (n: ServiceNode) => {
    let cur = n.parentId ? map.get(n.parentId) : undefined;
    while (cur) {
      if (isZone(cur) && cur.data.zoneKind === 'vpc') return cur.id;
      cur = cur.parentId ? map.get(cur.parentId) : undefined;
    }
    return null;
  };

  const portIn = ruleCovers;
  const peerMatches = (peer: SgRule['peer'], other: ServiceNode) => peerIs(peer, other, map, net.sgIdsOf);
  const describeRules = (gs: SecurityGroup[], dir: 'inbound' | 'outbound') => {
    const rs = gs.flatMap((g) => g[dir].map((r) => `${g.name}: ${ruleText(r, net.groups, CDN)}`));
    return rs.length ? rs.join(' · ') : 'ninguna regla';
  };
  const peerFor = (other: ServiceNode): SgRule['peer'] => {
    if (inVpc(other, map) && net.sgIdsOf(other)[0]) return { kind: 'sg', sgId: net.sgIdsOf(other)[0] };
    if (role(other) === 'cdn') return { kind: 'prefix', value: 'cdn' };
    return { kind: 'cidr', value: '0.0.0.0/0' };
  };
  const manual = net.mode === 'manual';
  const who = (n: ServiceNode) => (role(n) === 'dns' ? `los clientes de Internet (vía ${n.data.label})` : n.data.label);

  for (const e of edges) {
    const sem = semantics(e, map);
    if (!sem || sem.kind === 'none' || sem.kind === 'managed') {
      if (sem) verdicts.set(e.id, { edgeId: e.id, kind: sem.kind, fromId: sem.from.id, toId: sem.to.id, port: 0, ok: true, checks: [], summary: sem.kind === 'managed' ? 'Lo gestiona la nube (sin chequeo de red)' : 'Plano de control' });
      continue;
    }
    const { from: s, to: t } = sem;
    let port = sem.port;
    const checks: NetCheck[] = [];
    let failure: string | undefined;
    const fail = (c: Omit<NetCheck, 'ok' | 'severity'> & { severity?: NetCheck['severity'] }, code?: string) => {
      checks.push({ ok: false, severity: 'error', ...c });
      if (!failure && (c.severity ?? 'error') === 'error') failure = code;
    };
    const pass = (id: string, title: string, detail = '') => checks.push({ id, ok: true, severity: 'error', title, detail });

    if (sem.kind === 'connect') {
      // ── 1. Listener del balanceador
      if (isLb(t)) {
        const ls = listenersOf(t);
        const l = ls.find((x) => x.port === port);
        if (!l) {
          const proto: Listener['protocol'] = lid(t) === 'nlb' ? 'TCP' : port === 443 ? 'HTTPS' : 'HTTP';
          fail(
            {
              id: 'listener',
              title: `${t.data.label} no tiene listener en el puerto ${port}`,
              detail: `${who(s)} llama al puerto ${port}, pero los listeners son: ${ls.map((x) => `${x.protocol} ${x.port}`).join(', ') || 'ninguno'}. La conexión es rechazada.`,
              fix: { kind: 'set-net', nodeId: t.id, patch: { listeners: [...ls, { id: `l${port}`, port, protocol: proto, action: 'forward', cert: proto === 'HTTPS' }] }, label: `Agregar listener ${proto} ${port}` },
            },
            'Conexión rechazada',
          );
        } else {
          pass('listener', `Listener ${l.protocol} ${l.port}`);
          if ((l.protocol === 'HTTPS' || l.protocol === 'TLS') && !l.cert)
            fail(
              { id: 'cert', title: `El listener ${l.protocol} ${l.port} no tiene certificado`, detail: 'Sin certificado TLS el balanceador no puede terminar HTTPS.', fix: { kind: 'set-net', nodeId: t.id, patch: { listeners: ls.map((x) => (x.id === l.id ? { ...x, cert: true } : x)) }, label: 'Asociar certificado' } },
              'Error TLS',
            );
          if (l.action === 'redirect-https') {
            const https = ls.find((x) => x.port === 443 && x.action === 'forward');
            if (role(s) === 'cdn')
              fail(
                { id: 'redirect-loop', title: `Bucle de redirección entre ${who(s)} y ${t.data.label}`, detail: `${CDN} llama al origen por HTTP y el listener ${l.port} responde con redirección a HTTPS: el navegador queda en un bucle.`, fix: { kind: 'set-net', nodeId: s.id, patch: { originProtocol: 'https-only' }, label: `${CDN} → origen solo HTTPS` } },
                'ERR_TOO_MANY_REDIRECTS',
              );
            else if (!https) fail({ id: 'redirect', title: `${t.data.label} redirige a HTTPS pero no tiene listener 443`, detail: 'La redirección lleva a un puerto que no escucha.' }, 'Conexión rechazada');
          }
        }
        if (t.data.props.scheme === 'internal' && !inVpc(s, map))
          fail(
            { id: 'scheme', title: `${t.data.label} es interno`, detail: `Un balanceador interno solo tiene IPs privadas: ${who(s)} (fuera de la VPC) no lo alcanza.`, fix: { kind: 'service', fix: { label: 'Cambiar a internet-facing', setProps: [{ nodeId: t.id, props: { scheme: 'internet-facing' } }] }, label: 'Cambiar a internet-facing' } },
            'Timeout de conexión',
          );
      }

      // ── 2. Target group del balanceador hacia el destino
      if (isLb(s)) {
        const tg = targetOf(s, t);
        const lp = listenPort(t);
        port = tg.port;
        if (tg.port !== lp)
          fail(
            { id: 'tg-port', title: `El target group envía al puerto ${tg.port}, pero ${t.data.label} escucha en ${lp}`, detail: 'Los health checks fallan y el balanceador marca los targets como no sanos: los usuarios reciben 502/503.', fix: { kind: 'set-target', lbId: s.id, targetId: t.id, target: { ...tg, port: lp }, label: `Target group → puerto ${lp}` } },
            '503 Service Unavailable',
          );
        else pass('tg-port', `Target group → ${tg.protocol} ${tg.port}`);
        if (!tg.healthPath) checks.push({ id: 'health', ok: false, severity: 'warn', title: 'Target group sin ruta de health check', detail: 'Define una ruta (p. ej. /health) que valide las dependencias de la app.' });
      }

      // ── 3. Exposición desde fuera de la VPC
      if (!inVpc(s, map) && inVpc(t, map) && !isLb(t)) {
        const publicCompute = role(t) === 'compute' && placementOf(t, map) === 'subnet-public' && t.data.net?.publicIp;
        if (role(s) === 'compute' || role(s) === 'workflow')
          fail({ id: 'outside-vpc', title: `${who(s)} está fuera de la VPC`, detail: `No tiene interfaz en la VPC, así que no puede llegar a ${t.data.label}, que es privado. Ubícalo en una subnet privada (VPC config) con un ${SG}.` }, 'Timeout de conexión');
        else if (!publicCompute && ['actor', 'external', 'cdn', 'dns'].includes(role(s)))
          fail({ id: 'exposure', title: `${t.data.label} no es alcanzable desde ${who(s)}`, detail: 'Está en una subnet sin acceso público y no tiene balanceador delante.' }, 'Timeout de conexión');
      }

      // ── 4. SG de entrada del destino
      if (needsSg(t, map)) {
        const tgs = sgsOf(t);
        if (!tgs.length) {
          fail(
            { id: 'sg-missing', title: `${t.data.label} no tiene ${SG} asignado`, detail: `Sin ${SG} se aplica el grupo por defecto de la VPC, que solo acepta tráfico de su mismo grupo.`, fix: gById.has(`sg_${t.id}`) ? { kind: 'set-net', nodeId: t.id, patch: { sgIds: [`sg_${t.id}`] }, label: `Asignar ${gById.get(`sg_${t.id}`)!.name}` } : { kind: 'create-sg', nodeId: t.id, label: `Crear ${SG} para ${t.data.label}` } },
            'Timeout de conexión',
          );
        } else {
          const ok = tgs.some((g) => g.inbound.some((r) => portIn(r, port) && peerMatches(r.peer, s)));
          if (ok) pass('sg-in', `${SG} de ${t.data.label} permite ${port} desde ${who(s)}`);
          else
            fail(
              {
                id: 'sg-in',
                title: `El ${SG} de ${t.data.label} bloquea el puerto ${port} desde ${who(s)}`,
                detail: `Reglas de entrada: ${describeRules(tgs, 'inbound')}. Ninguna permite TCP ${port} desde ${who(s)}${inVpc(s, map) ? ` (${sgsOf(s).map((g) => g.name).join(', ') || 'sin ' + SG}, ${cidrOf(s, map) ?? ''})` : ''}. La conexión se descarta en silencio.`,
                fix: manual ? { kind: 'add-rule', sgId: tgs[0].id, dir: 'inbound', rule: { protocol: 'tcp', from: port, to: port, peer: peerFor(s), description: `Desde ${who(s)}` }, label: `Permitir ${port} desde ${who(s)}` } : undefined,
              },
              'Timeout de conexión',
            );
        }
      }

      // ── 5. SG de salida del origen
      if (needsSg(s, map) && sgsOf(s).length) {
        const sgs = sgsOf(s);
        const ok = sgs.some((g) => g.outbound.some((r) => portIn(r, port) && peerMatches(r.peer, t)));
        if (!ok)
          fail(
            {
              id: 'sg-out',
              title: `El ${SG} de ${who(s)} no permite salir al puerto ${port}`,
              detail: `Reglas de salida: ${describeRules(sgs, 'outbound')}.`,
              fix: manual ? { kind: 'add-rule', sgId: sgs[0].id, dir: 'outbound', rule: { protocol: 'tcp', from: port, to: port, peer: peerFor(t), description: `Hacia ${t.data.label}` }, label: `Permitir salida ${port} hacia ${t.data.label}` } : undefined,
            },
            'Timeout de conexión',
          );
      }

      // ── 6. La flecha dice otro puerto
      const proto = String((e.data as ConnData)?.protocol ?? '');
      const m = proto.match(/\b(\d{2,5})\b/);
      if (m && Number(m[1]) !== port && !isLb(t) && !isLb(s))
        checks.push({ id: 'label', ok: false, severity: 'warn', title: `La flecha dice ${m[1]} pero ${t.data.label} escucha en ${port}`, detail: 'Actualiza la etiqueta o el puerto de la pieza para que el diagrama no engañe.', fix: { kind: 'set-edge', edgeId: e.id, protocol: proto.replace(m[1], String(port)), label: `Etiqueta → ${port}` } });
    }

    if (sem.kind === 'egress') {
      const place = placementOf(s, map);
      const vpc = vpcOf(s);
      const inSame = (x: ServiceNode) => vpcOf(x) === vpc;
      const nat = services.find((x) => lid(x) === 'natgw' && inSame(x));
      const ep = services.find((x) => lid(x) === 'vpce' && inSame(x) && (ENDPOINT_FOR[lid(t)] ?? []).includes(String(x.data.props.service)));
      const vpn = services.find((x) => lid(x) === 'vpn') && t.data.serviceId === 'onprem';
      const publicPath = place === 'subnet-public' && s.data.net?.publicIp;
      if (nat || ep || vpn || publicPath) pass('route', ep ? `Ruta privada por ${ep.data.label}` : nat ? `Salida por ${nat.data.label}` : vpn ? 'Por la VPN' : 'IP pública');
      else {
        const pub = nodes.find((z) => isZone(z) && z.data.zoneKind === 'subnet-public' && vpcOf(z as unknown as ServiceNode) === vpc);
        fail(
          {
            id: 'route',
            title: `${s.data.label} no tiene ruta hacia ${t.data.label}`,
            detail: `Está en una subnet ${place === 'subnet-public' ? 'pública sin IP pública' : 'privada'} y la ${azure ? 'VNet' : 'VPC'} no tiene NAT Gateway${ENDPOINT_FOR[lid(t)] ? ` ni ${azure ? 'Private Endpoint' : 'VPC Endpoint'} para ${t.data.label}` : ''}.`,
            fix: pub ? { kind: 'service', fix: { label: 'Agregar NAT Gateway', add: [{ serviceId: 'natgw', parent: pub.id }], connect: [{ source: s.id, target: 'new:0' }] }, label: 'Agregar NAT Gateway' } : undefined,
          },
          'Timeout de conexión',
        );
      }
      if (needsSg(s, map) && sgsOf(s).length) {
        const sgs = sgsOf(s);
        const ok = sgs.some((g) => g.outbound.some((r) => portIn(r, port) && (r.peer.kind === 'cidr' ? isAnyCidr(r.peer.value) : false)));
        if (!ok)
          fail(
            { id: 'sg-out', title: `El ${SG} de ${s.data.label} no permite HTTPS de salida`, detail: `Reglas de salida: ${describeRules(sgs, 'outbound')}. Para llegar a ${t.data.label} necesita TCP 443 de salida.`, fix: manual ? { kind: 'add-rule', sgId: sgs[0].id, dir: 'outbound', rule: { protocol: 'tcp', from: 443, to: 443, peer: { kind: 'cidr', value: '0.0.0.0/0' }, description: 'HTTPS de salida' }, label: 'Permitir HTTPS de salida' } : undefined },
            'Timeout de conexión',
          );
      }
    }

    const firstErr = checks.find((c) => !c.ok && c.severity === 'error');
    verdicts.set(e.id, {
      edgeId: e.id,
      kind: sem.kind,
      fromId: s.id,
      toId: t.id,
      port,
      ok: !firstErr,
      checks,
      summary: firstErr ? firstErr.title : sem.kind === 'egress' ? `Salida HTTPS hacia ${t.data.label}` : `TCP ${port} permitido`,
      failure,
      short: firstErr ? shortOf(firstErr.id, port, SG, isLb(s) ? listenPort(t) : port) : undefined,
    });
  }

  // ── Revisión general de la configuración
  const general: NetCheck[] = [];
  if (manual) {
    for (const g of net.groups) {
      for (const dir of ['inbound', 'outbound'] as const)
        for (const r of g[dir])
          if (r.peer.kind === 'sg' && !gById.has(r.peer.sgId)) general.push({ id: `dangling:${r.id}`, ok: false, severity: 'warn', title: `${g.name}: regla hacia un ${SG} eliminado`, detail: ruleText(r, net.groups, CDN) });
      const users = services.filter((n) => net.sgIdsOf(n).includes(g.id));
      if (!users.length) general.push({ id: `unused:${g.id}`, ok: false, severity: 'warn', title: `${g.name} no está asignado a ninguna pieza`, detail: 'Asígnalo o elimínalo.' });
      for (const n of users) {
        const r = role(n);
        for (const rule of g.inbound) {
          if (rule.peer.kind !== 'cidr' || !isAnyCidr(rule.peer.value)) continue;
          if (['datastore', 'cache', 'search'].includes(r))
            general.push({ nodeIds: [n.id], id: `open-db:${g.id}:${rule.id}`, ok: false, severity: 'error', title: `${g.name} abre ${n.data.label} a todo Internet`, detail: `La regla ${ruleText(rule, net.groups, CDN)} expone la base de datos. Permite solo el ${SG} de la aplicación.` });
          else if (rule.protocol === 'all' || (rule.from <= 22 && rule.to >= 22) || (rule.from <= 3389 && rule.to >= 3389))
            general.push({ nodeIds: [n.id], id: `open-admin:${g.id}:${rule.id}`, ok: false, severity: 'warn', title: `${g.name} permite ${rule.protocol === 'all' ? 'todo el tráfico' : 'administración remota (SSH/RDP)'} desde Internet`, detail: `Usa ${azure ? 'Azure Bastion' : 'SSM Session Manager'} en lugar de abrir puertos de administración.` });
          else if (role(n) === 'compute' && placementOf(n, map) !== 'subnet-public')
            general.push({ nodeIds: [n.id], id: `open-app:${g.id}:${rule.id}`, ok: false, severity: 'warn', title: `${g.name} acepta ${rule.from} desde cualquier IP`, detail: `${n.data.label} solo debería aceptar tráfico del balanceador (${SG} como origen).` });
        }
      }
    }
    for (const n of services) if (needsSg(n, map) && !net.sgIdsOf(n).length) general.push({ nodeIds: [n.id], id: `nosg:${n.id}`, ok: false, severity: 'warn', title: `${n.data.label} no tiene ${SG}`, detail: `Se le aplicaría el grupo por defecto. Asígnale un ${SG}.` });
  }
  // Auto Scaling coherente
  for (const n of services) {
    const p = n.data.props;
    if (('minSize' in p || 'maxSize' in p || 'maxTasks' in p) && p.autoscaling !== false) {
      const min = p.minSize !== undefined ? Number(p.minSize) : 0;
      const max = Number(p.maxSize ?? p.maxTasks);
      const des = Number(p.count ?? p.desired);
      if (Number.isFinite(max) && Number.isFinite(des) && (min > max || des < min || des > max))
        general.push({
          id: `asg:${n.id}`,
          nodeIds: [n.id],
          ok: false,
          severity: 'error',
          title: `${n.data.label}: Auto Scaling incoherente`,
          detail: `Debe cumplirse mínimo ≤ deseado ≤ máximo (hoy ${'minSize' in p ? `${min} ≤ ` : ''}${des} ≤ ${max}). AWS/Azure rechazan esta configuración.`,
          fix: { kind: 'service', fix: { label: 'Ajustar límites', setProps: [{ nodeId: n.id, props: 'minSize' in p ? { minSize: Math.min(min, des), maxSize: Math.max(max, des) } : { maxTasks: Math.max(max, des) } }] }, label: 'Ajustar límites' },
        });
      else if (Number.isFinite(max) && max === des && des > 0 && p.autoscaling !== undefined)
        general.push({ nodeIds: [n.id], id: `asg-flat:${n.id}`, ok: false, severity: 'warn', title: `${n.data.label}: el máximo es igual al deseado`, detail: 'El grupo nunca podrá crecer ante un pico de tráfico.' });
    }
  }
  return { mode: net.mode, net, verdicts, general };
}

function shortOf(id: string, port: number, SG: string, listen: number): string {
  switch (id) {
    case 'listener':
      return `sin listener :${port}`;
    case 'cert':
      return 'sin certificado TLS';
    case 'redirect-loop':
      return 'bucle HTTP→HTTPS';
    case 'redirect':
      return 'redirige a :443 inexistente';
    case 'scheme':
      return 'LB interno';
    case 'tg-port':
      return `TG :${port} ≠ app :${listen}`;
    case 'outside-vpc':
      return 'fuera de la VPC';
    case 'exposure':
      return 'no expuesto';
    case 'sg-missing':
      return `sin ${SG}`;
    case 'sg-in':
      return `${SG} bloquea :${port}`;
    case 'sg-out':
      return `${SG} sin salida :${port}`;
    case 'route':
      return 'sin ruta de salida';
    default:
      return 'bloqueado';
  }
}

/** Aplica la generación automática como configuración manual inicial. */
export function materialize(nodes: AppNode[], edges: AppEdge[]) {
  return generateSecurityGroups(nodes, edges);
}
