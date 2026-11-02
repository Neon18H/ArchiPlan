import { getService } from '../catalog/catalog';
import { byId, isService, isZone, placementOf } from '../lib/graph';
import type { AppEdge, AppNode, Decision, Issue, ZoneKind } from '../types';
import type { Threat } from '../threats/model';

export interface GuideStep {
  id: string;
  title: string;
  question: string;
  optional?: boolean;
  done: boolean;
  /** Piezas sugeridas para este paso. */
  suggest: string[];
  zones?: ZoneKind[];
  tip: string;
}

export function buildGuide(nodes: AppNode[], edges: AppEdge[], decisions: Decision[], issues: Issue[], threats: Threat[] = []): GuideStep[] {
  const map = byId(nodes);
  const services = nodes.filter(isService);
  const roles = new Set(services.map((n) => getService(n.data.serviceId).role));
  const has = (...r: string[]) => r.some((x) => roles.has(x as never));
  const vpcBound = services.filter((n) => getService(n.data.serviceId).vpcBound);
  const vpcOk = vpcBound.length === 0 ? has('compute') : vpcBound.every((n) => placementOf(n, map).startsWith('subnet-')) && nodes.some((n) => isZone(n) && n.data.zoneKind === 'vpc');
  const connected = services.length > 1 && services.every((n) => edges.some((e) => e.source === n.id || e.target === n.id) || ['cloudtrail', 'guardduty', 'kms', 'acm', 'igw'].includes(n.data.serviceId));

  return [
    { id: 'actors', title: '1. Actores', question: '¿Quién usa el sistema y con qué sistemas externos se integra?', done: has('actor', 'external'), suggest: ['user', 'admin', 'external', 'onprem'], tip: 'Empieza por el contexto (C1): personas y sistemas fuera de tu control.' },
    { id: 'entry', title: '2. Punto de entrada', question: '¿Por dónde entra el tráfico?', done: has('dns', 'cdn', 'api', 'lb'), suggest: ['route53', 'cloudfront', 'apigw', 'alb'], tip: 'DNS → CDN → WAF → balanceador/API es el camino típico de una app web.' },
    { id: 'edge-sec', title: '3. Protección del borde', question: '¿Cómo proteges la entrada (OWASP, DDoS, TLS)?', done: has('waf'), suggest: ['waf', 'acm', 'shield'], tip: 'Asocia el WAF al componente más externo (CloudFront o API Gateway).' },
    { id: 'identity', title: '4. Identidad', question: '¿Cómo se autentican y autorizan los usuarios?', done: has('identity') || !has('actor'), suggest: ['cognito'], tip: 'Usa un IdP con OIDC; valida el JWT en la API (authorizer).' },
    { id: 'compute', title: '5. Lógica de negocio', question: '¿Dónde se ejecuta la aplicación?', done: has('compute'), suggest: ['ecs', 'lambda', 'ec2', 'eks', 'apprunner'], tip: 'Lambda para cargas por eventos; ECS Fargate para servicios siempre activos.' },
    { id: 'data', title: '6. Datos', question: '¿Dónde y cómo se guardan los datos?', done: has('datastore', 'storage'), suggest: ['aurora', 'rds', 'dynamodb', 's3', 'elasticache'], tip: 'Relacional para transacciones; DynamoDB para acceso por clave a gran escala; caché para lecturas calientes.' },
    { id: 'network', title: '7. Red', question: '¿En qué región, VPC y subnets vive cada pieza?', done: vpcOk, suggest: [], zones: ['region', 'vpc', 'subnet-public', 'subnet-private', 'subnet-data'], tip: 'Pública: solo balanceadores y NAT. Privada: cómputo. Datos: bases de datos.' },
    { id: 'async', title: '8. Integración asíncrona', question: '¿Hay procesos que no deban bloquear al usuario?', optional: true, done: has('queue', 'topic', 'eventbus', 'stream', 'workflow'), suggest: ['sqs', 'sns', 'eventbridge', 'stepfunctions', 'kinesis'], tip: 'Desacopla con colas para absorber picos y reintentar fallos.' },
    { id: 'secrets', title: '9. Secretos y cifrado', question: '¿Dónde viven credenciales y llaves?', done: has('secrets', 'kms'), suggest: ['secrets', 'kms'], tip: 'Nada de credenciales en código o variables de entorno en texto plano.' },
    { id: 'obs', title: '10. Observabilidad', question: '¿Cómo sabrás que algo falla?', done: has('observability'), suggest: ['cloudwatch', 'xray', 'cloudtrail', 'guardduty'], tip: 'Logs + métricas + trazas + alarmas, y auditoría con CloudTrail.' },
    { id: 'connect', title: '11. Conexiones válidas', question: '¿Todo está conectado y sin errores?', done: connected && !issues.some((i) => i.severity === 'error'), suggest: [], tip: 'Revisa la pestaña Validación hasta que no queden errores.' },
    { id: 'threats', title: '12. Modelo de amenazas', question: '¿Trataste las amenazas críticas y altas (STRIDE)?', done: services.length > 0 && !threats.some((t) => (t.status === 'abierta' || t.status === 'parcial') && (t.risk === 'Crítico' || t.risk === 'Alto')), suggest: [], tip: 'Mitiga, acepta con justificación o marca "no aplica" cada amenaza crítica y alta en la pestaña Amenazas.' },
    { id: 'adr', title: '13. Decisiones (ADR)', question: '¿Documentaste por qué elegiste estas piezas?', done: decisions.length > 0, suggest: [], tip: 'Un ADR por decisión importante: contexto, decisión y consecuencias.' },
  ];
}
