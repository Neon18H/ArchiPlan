import { scalingOf, scalingProblems } from '../scaling/model';
import { coverage } from '../c3/model';
import { cloudText, getService, lid, PLACEMENT_LABEL, primaryCloud, ZONE_PARENT, ZONES } from '../catalog/catalog';
import { ancestors, byId, isService, isZone, placementOf } from '../lib/graph';
import type { AppEdge, AppNode, Issue, ServiceNode, ZoneNode } from '../types';
import { evaluateConnection } from './connections';

const name = (n: ServiceNode) => `${n.data.label}`;

export function validate(nodes: AppNode[], edges: AppEdge[]): Issue[] {
  const issues: Issue[] = [];
  const map = byId(nodes);
  const services = nodes.filter(isService);
  const zones = nodes.filter(isZone);
  const svc = (n: ServiceNode) => getService(n.data.serviceId);
  const hasRole = (role: string) => services.some((n) => svc(n).role === role);
  const ofId = (id: string) => services.filter((n) => lid(n) === id);
  const outgoing = (id: string) => edges.filter((e) => e.source === id);
  const incoming = (id: string) => edges.filter((e) => e.target === id);
  const push = (i: Omit<Issue, 'id'> & { id?: string }) => issues.push({ id: i.id ?? `${i.title}:${i.nodeIds.join(',')}:${(i.edgeIds ?? []).join(',')}`, ...i });

  // ── 1. Anidamiento de zonas
  for (const z of zones) {
    const parent = z.parentId ? map.get(z.parentId) : undefined;
    const pk = parent && isZone(parent) ? parent.data.zoneKind : null;
    if (!ZONE_PARENT[z.data.zoneKind].includes(pk)) {
      const allowed = ZONE_PARENT[z.data.zoneKind].map((k) => (k ? ZONES[k].label : 'el lienzo')).join(' o ');
      push({ severity: 'error', title: `${z.data.label}: ubicación de zona inválida`, detail: `Una "${ZONES[z.data.zoneKind].label}" debe estar dentro de ${allowed}.`, nodeIds: [z.id] });
    }
  }

  // ── 2. Ubicación de cada pieza
  for (const n of services) {
    const def = svc(n);
    const place = placementOf(n, map);
    const inSubnet = place.startsWith('subnet-');
    if (def.vpcBound && !inSubnet) {
      push({ severity: 'warn', title: `${name(n)} debe vivir en una subnet`, detail: `${def.name} se despliega dentro de una VPC. Ubícalo en: ${def.zones.map((z) => PLACEMENT_LABEL[z]).join(', ')}.`, nodeIds: [n.id] });
    } else if (!def.zones.includes(place) && !(place === 'region' && def.zones.includes('outside'))) {
      push({ severity: 'error', title: `${name(n)} está en una zona no válida`, detail: `${def.name} no puede ir en ${PLACEMENT_LABEL[place]}. Ubicaciones válidas: ${def.zones.map((z) => PLACEMENT_LABEL[z]).join(', ')}.`, nodeIds: [n.id] });
    }
    if (def.role === 'lb') {
      const scheme = n.data.props.scheme;
      if (scheme === 'internet-facing' && place !== 'subnet-public' && inSubnet) {
        push({ severity: 'error', title: `${name(n)} público en subnet privada`, detail: 'Un balanceador internet-facing debe estar en una subnet pública.', nodeIds: [n.id], fix: { label: 'Cambiar a internal', setProps: [{ nodeId: n.id, props: { scheme: 'internal' } }] } });
      }
      if (scheme === 'internal' && place === 'subnet-public') {
        push({ severity: 'warn', title: `${name(n)} interno en subnet pública`, detail: 'Un balanceador interno debería ir en subnet privada.', nodeIds: [n.id] });
      }
    }
  }

  // ── 3. Reevaluar todas las conexiones (las piezas pueden haberse movido o cambiado)
  const seen = new Set<string>();
  for (const e of edges) {
    const s = map.get(e.source);
    const t = map.get(e.target);
    if (!s || !t) continue;
    const key = `${e.source}->${e.target}`;
    if (seen.has(key)) push({ severity: 'warn', title: 'Conexión duplicada', detail: 'Hay dos conexiones iguales entre las mismas piezas.', nodeIds: [e.source, e.target], edgeIds: [e.id] });
    seen.add(key);
    const v = evaluateConnection(s, t, map);
    const replica = isService(s) && isService(t) && ((s.data.props.replicaOf === t.id) || (t.data.props.replicaOf === s.id));
    if (replica) continue;
    if (v.level !== 'ok' && v.msg && v.msg.startsWith('Replicación entre bases de datos')) {
      const sl = (s.data as { label: string }).label;
      const tl = (t.data as { label: string }).label;
      push({ severity: 'warn', title: `${sl} → ${tl}: ¿es una réplica?`, detail: 'Configura qué tipo de réplica es y cómo hace failover en ⛑ Resiliencia → Replicación y failover; si no, la simulación no la usa.', nodeIds: [e.source, e.target], edgeIds: [e.id] });
      continue;
    }
    if (v.level !== 'ok' && v.msg) {
      const sl = (s.data as { label: string }).label;
      const tl = (t.data as { label: string }).label;
      push({ severity: v.level === 'error' ? 'error' : 'warn', title: `${sl} → ${tl}`, detail: v.msg, nodeIds: [e.source, e.target], edgeIds: [e.id] });
    }
  }

  // ── 4. Seguridad del borde: WAF en los puntos de entrada públicos
  const entries = services.filter((n) => {
    const d = svc(n);
    if (d.role === 'cdn' || d.role === 'api') return !incoming(n.id).some((e) => svc(map.get(e.source) as ServiceNode)?.role === 'cdn');
    if (d.role === 'lb' && n.data.props.scheme === 'internet-facing') return !incoming(n.id).some((e) => svc(map.get(e.source) as ServiceNode)?.role === 'cdn');
    return false;
  });
  for (const n of entries) {
    const protectedByWaf = incoming(n.id).some((e) => svc(map.get(e.source) as ServiceNode)?.role === 'waf');
    if (!protectedByWaf) {
      const existingWaf = ofId('waf')[0];
      push({
        severity: 'warn',
        title: `${name(n)} expuesto sin WAF`,
        detail: 'Todo punto de entrada público debería tener un WAF (reglas OWASP, rate limiting, bloqueo de bots).',
        nodeIds: [n.id],
        fix: existingWaf
          ? { label: 'Asociar WAF existente', connect: [{ source: existingWaf.id, target: n.id }] }
          : { label: 'Agregar WAF', add: [{ serviceId: 'waf', near: n.id, parent: null }], connect: [{ source: 'new:0', target: n.id }] },
      });
    }
  }

  // ── 5. Bases de datos alcanzables desde Internet
  for (const n of services) {
    const d = svc(n);
    if (!['datastore', 'cache', 'search'].includes(d.role)) continue;
    const exposed = incoming(n.id).some((e) => {
      const s = map.get(e.source) as ServiceNode;
      return s && ['actor', 'external', 'dns', 'cdn', 'lb', 'api'].includes(svc(s).role) && !(svc(s).id === 'apigw' && d.id === 'dynamodb') && !(['iotcore', 'appsync'].includes(svc(s).id) && !d.vpcBound);
    });
    if (exposed) push({ severity: 'error', title: `${name(n)} expuesto a Internet`, detail: 'La capa de datos solo debe ser accesible desde la capa de aplicación.', nodeIds: [n.id] });
  }

  // ── 6. Cómputo en subnet privada sin salida a Internet / servicios AWS
  for (const n of services) {
    const d = svc(n);
    if (d.role !== 'compute' || placementOf(n, map) !== 'subnet-private') continue;
    const vpc = ancestors(n, map).find((z) => z.data.zoneKind === 'vpc');
    if (!vpc) continue;
    const inVpc = (x: AppNode) => ancestors(x, map).some((z) => z.id === vpc.id);
    const hasNat = services.some((x) => lid(x) === 'natgw' && inVpc(x));
    const hasVpce = services.some((x) => lid(x) === 'vpce' && inVpc(x));
    const targets = outgoing(n.id).map((e) => map.get(e.target)).filter(isService);
    const needsInternet = targets.some((t) => svc(t).role === 'external' || svc(t).id === 'bedrock');
    const needsAws = targets.some((t) => placementOf(t, map) === 'outside' || placementOf(t, map) === 'region');
    const publicSubnet = zones.find((z) => z.data.zoneKind === 'subnet-public' && z.parentId === vpc.id);
    if (needsInternet && !hasNat) {
      push({
        severity: 'warn',
        title: `${name(n)} no tiene salida a Internet`,
        detail: 'Está en subnet privada y llama a un sistema externo, pero la VPC no tiene NAT Gateway.',
        nodeIds: [n.id],
        fix: publicSubnet ? { label: 'Agregar NAT Gateway', add: [{ serviceId: 'natgw', parent: publicSubnet.id, near: n.id }], connect: [{ source: n.id, target: 'new:0' }] } : undefined,
      });
    } else if (needsAws && !hasNat && !hasVpce) {
      push({
        severity: 'warn',
        title: `${name(n)} no tiene ruta a servicios AWS`,
        detail: 'Desde una subnet privada se necesita un NAT Gateway o VPC Endpoints para llegar a S3, DynamoDB, SQS, Secrets Manager, etc.',
        nodeIds: [n.id],
        fix: { label: 'Agregar VPC Endpoint', add: [{ serviceId: 'vpce', parent: n.parentId ?? null, near: n.id }] },
      });
    }
  }

  // ── 6b. Escalado configurado
  for (const n of services)
    for (const pr of scalingProblems(n))
      push({ severity: pr.severity, title: pr.title, detail: pr.detail, nodeIds: [n.id], ...(pr.props ? { fix: { label: 'Corregir escalado', setProps: [{ nodeId: n.id, props: pr.props }] } } : {}) });

  // ── 7. Alta disponibilidad
  for (const n of services) {
    const p = n.data.props;
    switch (lid(n)) {
      case 'ec2': {
        const sc = scalingOf(n);
        if (sc && sc.desired < 2 && (sc.policy === 'manual' || sc.policy === 'fixed'))
          push({ severity: 'warn', title: `${name(n)} es un punto único de falla`, detail: 'Una sola instancia y sin autoescalado. Usa ≥2 instancias en distintas AZ.', nodeIds: [n.id], fix: { label: 'Escalar por CPU con 2+', setProps: [{ nodeId: n.id, props: { count: 2, autoscaling: true, scalePolicy: 'cpu', minSize: 2 } }] } });
        break;
      }
      case 'ecs':
        if (Number(p.desired) < 2)
          push({ severity: 'warn', title: `${name(n)} con una sola tarea`, detail: 'Con 1 tarea no hay tolerancia a fallos ni despliegues sin corte.', nodeIds: [n.id], fix: { label: 'Usar 2 tareas', setProps: [{ nodeId: n.id, props: { desired: 2, minSize: 2 } }] } });
        break;
      case 'rds':
        if (!p.multiAZ)
          push({ severity: 'warn', title: `${name(n)} sin Multi‑AZ`, detail: 'Si cae la zona de disponibilidad, cae la base de datos.', nodeIds: [n.id], fix: { label: 'Activar Multi‑AZ', setProps: [{ nodeId: n.id, props: { multiAZ: true } }] } });
        break;
      case 'aurora':
        if (Number(p.replicas) < 1)
          push({ severity: 'info', title: `${name(n)} sin réplicas`, detail: 'Sin réplica el failover de Aurora tarda más.', nodeIds: [n.id], fix: { label: 'Agregar 1 réplica', setProps: [{ nodeId: n.id, props: { replicas: 1 } }] } });
        break;
      case 'sqs':
        if (!p.dlq)
          push({ severity: 'info', title: `${name(n)} sin dead‑letter queue`, detail: 'Los mensajes que fallan repetidamente se reintentarán sin fin o se perderán.', nodeIds: [n.id], fix: { label: 'Activar DLQ', setProps: [{ nodeId: n.id, props: { dlq: true } }] } });
        break;
      case 's3':
        if (p.public)
          push({ severity: 'warn', title: `${name(n)} es público`, detail: 'Evita buckets públicos: sirve el contenido por CloudFront con Origin Access Control.', nodeIds: [n.id], fix: { label: 'Bloquear acceso público', setProps: [{ nodeId: n.id, props: { public: false } }] } });
        break;
    }
    if (p.encrypted === false)
      push({ severity: 'warn', title: `${name(n)} sin cifrado en reposo`, detail: 'Activa el cifrado (KMS) para cumplir con buenas prácticas y normativas.', nodeIds: [n.id], fix: { label: 'Activar cifrado', setProps: [{ nodeId: n.id, props: { encrypted: true } }] } });
  }
  for (const z of zones) {
    if (z.data.zoneKind === 'vpc' && Number(z.data.props.azs) < 2)
      push({ severity: 'warn', title: `${z.data.label} en una sola AZ`, detail: 'Usa al menos 2 zonas de disponibilidad.', nodeIds: [z.id], fix: { label: 'Usar 2 AZ', setProps: [{ nodeId: z.id, props: { azs: 2 } }] } });
  }

  // ── 8. Secretos para credenciales de bases de datos
  const secretsNode = ofId('secrets')[0];
  for (const n of services) {
    if (svc(n).role !== 'compute') continue;
    const usesSqlDb = outgoing(n.id).some((e) => ['rds', 'aurora', 'documentdb', 'redshift'].includes(lid(map.get(e.target) as ServiceNode)));
    const readsSecrets = outgoing(n.id).some((e) => lid(map.get(e.target) as ServiceNode) === 'secrets');
    if (usesSqlDb && !readsSecrets)
      push({
        severity: 'info',
        title: `${name(n)}: credenciales de BD`,
        detail: 'Guarda las credenciales en Secrets Manager con rotación, nunca en variables de entorno ni en el código.',
        nodeIds: [n.id],
        fix: secretsNode ? { label: 'Conectar a Secrets Manager', connect: [{ source: n.id, target: secretsNode.id }] } : { label: 'Agregar Secrets Manager', add: [{ serviceId: 'secrets', near: n.id }], connect: [{ source: n.id, target: 'new:0' }] },
      });
    if (lid(n) === 'lambda' && outgoing(n.id).some((e) => ['rds', 'aurora'].includes(lid(map.get(e.target) as ServiceNode))))
      push({ severity: 'info', title: `${name(n)} → BD relacional`, detail: 'Lambda puede agotar las conexiones de la BD. Usa RDS Proxy o Aurora Data API.', nodeIds: [n.id] });
  }

  // ── 9. Observabilidad
  const computes = services.filter((n) => svc(n).role === 'compute');
  const cw = ofId('cloudwatch')[0];
  if (computes.length && !cw) {
    push({
      severity: 'warn',
      title: 'Sin observabilidad',
      detail: 'No hay CloudWatch: no tendrás logs, métricas ni alarmas.',
      nodeIds: computes.map((c) => c.id),
      id: 'no-observability',
      fix: { label: 'Agregar CloudWatch', add: [{ serviceId: 'cloudwatch', near: computes[0].id }], connect: computes.map((c) => ({ source: c.id, target: 'new:0' })) },
    });
  } else if (cw) {
    const missing = computes.filter((c) => !outgoing(c.id).some((e) => svc(map.get(e.target) as ServiceNode)?.role === 'observability'));
    if (missing.length)
      push({ severity: 'info', title: 'Cómputo sin logs', detail: `${missing.map(name).join(', ')} no envía logs/métricas a CloudWatch.`, nodeIds: missing.map((m) => m.id), id: 'compute-no-logs', fix: { label: 'Conectar a CloudWatch', connect: missing.map((m) => ({ source: m.id, target: cw.id })) } });
  }

  // ── 10. Identidad
  const actors = services.filter((n) => svc(n).role === 'actor');
  if (actors.length && entries.length && !hasRole('identity')) {
    const api = entries.find((n) => svc(n).role === 'api') ?? entries[0];
    push({ severity: 'info', title: 'Sin proveedor de identidad', detail: 'Hay usuarios pero no se ve cómo se autentican. Considera Cognito u otro IdP (OIDC).', nodeIds: [api.id], id: 'no-identity', fix: { label: 'Agregar Cognito', add: [{ serviceId: 'cognito', near: api.id }], connect: [{ source: api.id, target: 'new:0', protocol: 'authorizer (JWT)' }] } });
  }

  // ── 11. Piezas sueltas y actores
  for (const n of services) {
    if (['cloudtrail', 'guardduty', 'kms', 'igw', 'codepipeline', 'acm'].includes(lid(n))) continue;
    if (!edges.some((e) => e.source === n.id || e.target === n.id))
      push({ severity: 'info', title: `${name(n)} no está conectado`, detail: 'Conéctalo o elimínalo para que el diagrama cuente la historia completa.', nodeIds: [n.id] });
  }
  if (services.length > 0 && !actors.length && !hasRole('external'))
    push({ severity: 'info', title: 'No hay actores', detail: '¿Quién usa el sistema? Agrega usuarios o sistemas externos para dar contexto (nivel C1).', nodeIds: [], id: 'no-actors' });

  // ── 12. Coherencia entre C2 y C3
  for (const n of services) {
    if (!n.data.c3?.components.length) continue;
    const cov = coverage(n, nodes, edges);
    if (cov.missing.length)
      push({ severity: 'info', title: `${name(n)} (C3): dependencias sin componente`, detail: `En C2 se conecta con ${cov.missing.map((m) => m.node.data.label).join(', ')}, pero ningún componente interno las usa. Actualiza la vista de componentes.`, nodeIds: [n.id] });
    if (cov.stale.length) push({ severity: 'info', title: `${name(n)} (C3): relaciones obsoletas`, detail: `${cov.stale.length} relación(es) de C3 apuntan a dependencias que ya no existen en C2.`, nodeIds: [n.id] });
  }

  const cloud = primaryCloud(nodes);
  if (cloud === 'azure') for (const i of issues) {
    i.title = cloudText(i.title, cloud);
    i.detail = cloudText(i.detail, cloud);
    if (i.fix) i.fix = { ...i.fix, label: cloudText(i.fix.label, cloud) };
  }
  const order = { error: 0, warn: 1, info: 2 };
  return issues.sort((a, b) => order[a.severity] - order[b.severity]);
}

export function summarize(issues: Issue[]) {
  return {
    error: issues.filter((i) => i.severity === 'error').length,
    warn: issues.filter((i) => i.severity === 'warn').length,
    info: issues.filter((i) => i.severity === 'info').length,
  };
}

export type { ZoneNode };
