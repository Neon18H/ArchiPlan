import { getService } from '../catalog/catalog';
import { placementOf } from '../lib/graph';
import type { AppNode, Role, ServiceDef } from '../types';

export type ConnVerdict = { level: 'ok' | 'warn' | 'error'; msg: string; protocol: string; async?: boolean };

type Rule = 'ok' | 'warn' | 'error' | [level: 'ok' | 'warn' | 'error', msg: string];

/**
 * Matriz rol‑origen → rol‑destino.
 * Lo que no está definido se permite con advertencia ("conexión poco común").
 */
const M: Partial<Record<Role, Partial<Record<Role | '*', Rule>>>> = {
  actor: {
    dns: 'ok', cdn: 'ok', api: 'ok', identity: 'ok', analytics: 'ok', ai: ['warn', 'Expón el modelo a través de tu API, no directamente al usuario.'],
    lb: ['ok', ''],
    waf: ['error', 'El usuario no se conecta al WAF: el WAF se asocia a CloudFront, ALB o API Gateway.'],
    compute: ['warn', 'Expón el cómputo detrás de un balanceador o API Gateway, no directamente.'],
    datastore: ['error', 'Un usuario nunca debe acceder directamente a una base de datos. Pon una API/servicio en medio.'],
    cache: ['error', 'Un usuario no debe acceder directamente a la caché.'],
    search: ['error', 'Expón la búsqueda a través de un servicio de aplicación.'],
    storage: ['warn', 'Mejor sirve los archivos vía CloudFront o URLs prefirmadas.'],
    queue: ['error', 'Los clientes no escriben directo en la cola: usa una API que publique el mensaje.'],
    topic: ['error', 'Los clientes no publican directo en SNS: usa una API.'],
    eventbus: ['error', 'Los clientes no publican directo en el bus: usa una API.'],
    stream: ['warn', 'Normalmente los clientes envían datos vía API, no directo al stream.'],
    secrets: ['error', 'Los secretos jamás se exponen a los usuarios.'],
    kms: ['error', 'Los usuarios no acceden a KMS.'],
    observability: ['error', 'Los usuarios no se conectan a la observabilidad.'],
    netgw: ['warn', 'Normalmente no se dibuja al usuario conectándose a un gateway de red.'],
    external: ['warn', 'Conexión entre actores externos: queda fuera del sistema.'],
    actor: ['error', 'Conexión entre actores: no pertenece a la arquitectura.'],
  },
  external: {
    dns: 'ok', cdn: 'ok', api: 'ok', lb: 'ok', netgw: 'ok', identity: 'ok', topic: ['warn', 'Mejor recibe webhooks por API Gateway.'],
    datastore: ['error', 'Un sistema externo no debe escribir directo en tu base de datos. Usa una API o un canal de integración.'],
    cache: ['error', 'Un sistema externo no debe acceder a la caché.'],
    secrets: ['error', 'Un sistema externo no debe leer tus secretos.'],
    compute: ['warn', 'Expón el cómputo detrás de API Gateway o un balanceador.'],
    actor: ['error', 'Conexión entre actores: no pertenece a la arquitectura.'],
  },
  dns: {
    cdn: 'ok', lb: 'ok', api: 'ok', compute: ['warn', 'Apunta el DNS a un balanceador o CDN, no a instancias.'], storage: ['warn', 'Mejor apunta a CloudFront delante de S3.'],
    '*': ['error', 'Route 53 solo resuelve nombres hacia puntos de entrada (CDN, balanceador, API).'],
  },
  cdn: {
    lb: 'ok', api: 'ok', storage: 'ok', observability: 'ok', compute: ['warn', 'Mejor pon un balanceador como origen.'], waf: ['warn', 'El WAF se asocia al CDN, no al revés: conecta WAF → CloudFront.'],
    datastore: ['error', 'Un CDN nunca debe tener una base de datos como origen.'],
    cache: ['error', 'Un CDN no usa ElastiCache como origen.'],
    '*': ['error', 'CloudFront solo usa como origen S3, un balanceador, API Gateway o un servidor web.'],
  },
  waf: {
    cdn: ['ok', ''], lb: ['ok', ''], api: ['ok', ''],
    '*': ['error', 'WAF solo se asocia a CloudFront, ALB o API Gateway.'],
  },
  lb: {
    compute: 'ok', identity: ['ok', ''], lb: ['warn', 'Encadenar balanceadores rara vez es necesario.'],
    datastore: ['error', 'Un balanceador solo distribuye tráfico hacia cómputo, no hacia bases de datos.'],
    cache: ['error', 'Un balanceador no apunta a la caché.'],
    queue: ['error', 'Un balanceador no envía tráfico a una cola. Usa API Gateway o un servicio.'],
    storage: ['error', 'Un balanceador no tiene S3 como destino. Usa CloudFront.'],
    observability: ['ok', ''],
    '*': ['warn', 'Normalmente un balanceador solo apunta a cómputo.'],
  },
  api: {
    compute: 'ok', queue: 'ok', topic: 'ok', eventbus: 'ok', workflow: 'ok', stream: 'ok', identity: 'ok', lb: 'ok', observability: 'ok',
    storage: ['warn', 'Integración directa con S3: útil para cargas; valida tamaños y permisos.'],
    datastore: ['error', 'API Gateway no se conecta a bases de datos relacionales: pon una Lambda o servicio en medio.'],
    cache: ['error', 'API Gateway no se conecta a ElastiCache: pon un servicio en medio.'],
    external: ['ok', ''],
  },
  compute: {
    '*': 'ok',
    dns: ['warn', 'El cómputo normalmente no se conecta a Route 53 en el diagrama.'],
    cdn: ['warn', 'El cómputo normalmente no llama a CloudFront.'],
    waf: ['error', 'WAF solo se asocia a CloudFront, ALB o API Gateway.'],
    actor: ['warn', 'Las respuestas a usuarios no se dibujan como conexión; usa notificaciones (SNS, WebSocket).'],
  },
  registry: {
    compute: ['ok', ''],
    '*': ['warn', 'El registro solo provee imágenes al cómputo.'],
  },
  datastore: {
    datastore: ['warn', 'Replicación entre bases de datos: documenta la estrategia.'],
    observability: 'ok', kms: 'ok', analytics: 'ok', storage: ['ok', ''],
    '*': ['error', 'Las bases de datos no inician conexiones: invierte la flecha (el servicio consulta a la BD).'],
  },
  cache: {
    observability: 'ok', kms: 'ok',
    '*': ['error', 'La caché no inicia conexiones: invierte la flecha.'],
  },
  search: { observability: 'ok', kms: 'ok', '*': ['error', 'El motor de búsqueda no inicia conexiones: invierte la flecha.'] },
  storage: {
    observability: 'ok', kms: 'ok', analytics: 'ok', storage: ['ok', ''],
    '*': ['error', 'El almacenamiento no inicia conexiones (salvo eventos de S3 hacia Lambda/SQS/SNS/EventBridge).'],
  },
  queue: {
    compute: 'ok', queue: ['ok', ''], observability: 'ok', workflow: 'ok',
    datastore: ['error', 'SQS no escribe en una base de datos: necesitas un consumidor (Lambda/ECS) entre la cola y la BD.'],
    storage: ['error', 'SQS no escribe en S3: necesitas un consumidor.'],
    '*': ['error', 'Una cola solo entrega mensajes a consumidores (cómputo) o a otra cola (DLQ).'],
  },
  topic: {
    queue: 'ok', compute: 'ok', external: 'ok', actor: ['ok', ''], stream: 'ok', observability: 'ok',
    datastore: ['error', 'SNS no escribe en bases de datos: suscribe una cola o una Lambda.'],
    '*': ['warn', 'SNS normalmente entrega a SQS, Lambda, HTTP, correo o SMS.'],
  },
  eventbus: {
    compute: 'ok', queue: 'ok', topic: 'ok', workflow: 'ok', stream: 'ok', api: 'ok', external: 'ok', eventbus: 'ok', observability: 'ok',
    datastore: ['error', 'EventBridge no escribe en bases de datos: enruta a una Lambda o cola.'],
    '*': ['warn', 'Destino poco común para EventBridge.'],
  },
  stream: {
    compute: 'ok', stream: 'ok', storage: 'ok', analytics: 'ok', search: 'ok', observability: 'ok',
    datastore: ['warn', 'Solo Firehose entrega a Redshift; para otras BD usa un consumidor.'],
    '*': ['warn', 'Destino poco común para un stream.'],
  },
  workflow: {
    compute: 'ok', queue: 'ok', topic: 'ok', eventbus: 'ok', datastore: ['ok', ''], storage: 'ok', ai: 'ok', workflow: 'ok', observability: 'ok', external: 'ok',
  },
  identity: {
    compute: ['ok', ''], observability: 'ok', topic: 'ok',
    '*': ['warn', 'El proveedor de identidad normalmente solo dispara triggers a Lambda.'],
  },
  secrets: { kms: 'ok', compute: ['ok', ''], observability: 'ok', '*': ['error', 'Secrets Manager no inicia conexiones: el servicio lee el secreto (invierte la flecha).'] },
  kms: { observability: 'ok', '*': ['error', 'KMS no inicia conexiones: los servicios usan la llave.'] },
  cert: { cdn: ['ok', ''], lb: ['ok', ''], api: ['ok', ''], '*': ['error', 'ACM solo provee certificados a CloudFront, balanceadores y API Gateway.'] },
  observability: {
    topic: 'ok', compute: ['ok', ''], observability: 'ok', storage: 'ok', stream: 'ok', search: 'ok',
    '*': ['warn', 'La telemetría normalmente fluye HACIA CloudWatch; revisa la dirección.'],
  },
  netgw: { '*': 'ok' },
  analytics: { storage: 'ok', datastore: 'ok', analytics: 'ok', observability: 'ok', '*': ['warn', 'Conexión poco común para un servicio analítico.'] },
  ai: { storage: 'ok', datastore: ['ok', ''], search: 'ok', observability: 'ok', '*': ['warn', 'Conexión poco común para un servicio de IA.'] },
  devops: { compute: 'ok', registry: 'ok', storage: 'ok', '*': ['warn', 'Conexión poco común para CI/CD.'] },
};

/** Excepciones por servicio (más específicas que la matriz de roles). */
function serviceOverride(src: ServiceDef, tgt: ServiceDef): Rule | null {
  if (src.emitsEvents && ['compute', 'queue', 'topic', 'eventbus', 'stream', 'workflow'].includes(tgt.role)) {
    return ['ok', ''];
  }
  if (src.id === 'apigw' && tgt.id === 'dynamodb') return ['ok', 'Integración directa de servicio (sin Lambda).'];
  if (src.id === 'firehose' && tgt.id === 'redshift') return 'ok';
  if (src.role === 'compute' && tgt.id === 'igw') return ['warn', 'El cómputo en subnet privada sale por un NAT Gateway, no directo por el IGW.'];
  if (src.id === 'shield') return ['cdn', 'lb', 'api', 'dns'].includes(tgt.role) ? 'ok' : ['error', 'Shield protege CloudFront, Route 53, ALB o API Gateway.'];
  if (src.id === 'guardduty') return ['topic', 'eventbus', 'observability', 'compute'].includes(tgt.role) ? 'ok' : ['warn', 'GuardDuty normalmente envía hallazgos a EventBridge/SNS.'];
  return null;
}

export function suggestProtocol(src: ServiceDef, tgt: ServiceDef): { protocol: string; async: boolean } {
  const asyncRoles: Role[] = ['queue', 'topic', 'eventbus', 'stream'];
  const isAsync = asyncRoles.includes(tgt.role) || asyncRoles.includes(src.role) || !!src.emitsEvents && tgt.role !== 'observability' && src.role !== 'actor';
  if (src.role === 'waf') return { protocol: 'protege', async: false };
  if (src.role === 'cert') return { protocol: 'TLS (certificado)', async: false };
  if (src.role === 'registry') return { protocol: 'pull de imagen', async: false };
  if (tgt.role === 'observability') return { protocol: 'logs/métricas', async: true };
  if (tgt.role === 'kms') return { protocol: 'cifrado', async: false };
  if (src.role === 'dns') return { protocol: 'DNS (alias)', async: false };
  if (src.role === 'queue' && tgt.role === 'compute') return { protocol: 'poll / trigger', async: true };
  if (src.emitsEvents && ['compute', 'queue', 'topic', 'eventbus'].includes(tgt.role)) return { protocol: 'evento', async: true };
  return { protocol: tgt.inboundProtocol || 'HTTPS', async: isAsync };
}

export function sqlPortFor(engine: unknown): string {
  const eng = String(engine ?? '');
  if (eng.includes('mysql') || eng.includes('mariadb')) return 'MySQL 3306';
  if (eng.includes('sqlserver')) return 'MSSQL 1433';
  if (eng.includes('oracle')) return 'Oracle 1521';
  return 'PostgreSQL 5432';
}

export function evaluateConnection(source: AppNode, target: AppNode, map: Map<string, AppNode>): ConnVerdict {
  if (source.type !== 'service' || target.type !== 'service') {
    return { level: 'error', msg: 'Las zonas no se conectan: conecta las piezas que están dentro.', protocol: '' };
  }
  if (source.id === target.id) return { level: 'error', msg: 'Una pieza no puede conectarse consigo misma.', protocol: '' };
  const src = getService(source.data.serviceId);
  const tgt = getService(target.data.serviceId);
  let { protocol, async } = suggestProtocol(src, tgt);
  if (tgt.id === 'rds' || tgt.id === 'aurora') protocol = sqlPortFor(target.data.props.engine ?? (tgt.id === 'aurora' ? 'aurora-postgresql' : 'postgres'));

  // Reglas por zona: desde afuera no hay ruta a subnets privadas.
  const fromOutside = src.role === 'actor' || src.role === 'external' || src.role === 'dns' || src.role === 'cdn';
  const tgtPlace = placementOf(target, map);
  if (fromOutside && (tgtPlace === 'subnet-private' || tgtPlace === 'subnet-data') && src.role !== 'external') {
    const isInternalLb = tgt.role === 'lb' && target.data.props.scheme === 'internal';
    if (tgt.role !== 'lb' || isInternalLb) {
      return {
        level: 'error',
        msg: `No existe ruta desde Internet hacia una ${tgtPlace === 'subnet-data' ? 'subnet de datos' : 'subnet privada'}. Entra por un balanceador público, CloudFront o API Gateway.`,
        protocol,
      };
    }
  }
  if (tgt.role === 'lb' && target.data.props.scheme === 'internal' && fromOutside) {
    return { level: 'error', msg: 'Este balanceador es "internal": no recibe tráfico desde Internet. Cámbialo a internet-facing.', protocol };
  }

  const rule = serviceOverride(src, tgt) ?? M[src.role]?.[tgt.role] ?? M[src.role]?.['*'] ?? ['warn', `Conexión poco común: ${src.name} → ${tgt.name}.`];
  const [level, msg] = typeof rule === 'string' ? [rule, ''] : rule;
  return { level, msg: msg || '', protocol, async };
}
