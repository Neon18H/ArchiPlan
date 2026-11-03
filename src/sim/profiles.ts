/**
 * Perfiles de simulación por servicio.
 *
 * IMPORTANTE: son ESTIMACIONES de orden de magnitud basadas en cuotas por defecto de AWS
 * y cargas web típicas. No reemplazan una prueba de carga real. Cada pieza permite
 * sobrescribir su capacidad desde el inspector (props `sim.capacity` y `sim.instances`).
 */
import { getService, lidOf } from '../catalog/catalog';
import { describeScaling, scalingOf } from '../scaling/model';
import type { ServiceNode } from '../types';

export type ScaleMode = 'none' | 'asg' | 'instant' | 'serverless-db';

export interface SimProfile {
  /** Capacidad por instancia en req/s (u operaciones/s). Infinity = no limita. */
  perInstance: number;
  /** Instancias activas al iniciar. */
  instances: number;
  /** Máximo de instancias si escala. */
  maxInstances: number;
  scale: ScaleMode;
  /** Segundos desde que se detecta la saturación hasta que entra la nueva capacidad. */
  scaleDelay: number;
  /** Latencia base (ms) sin carga. */
  latency: number;
  /** ¿Una instancia caída se reemplaza sola? Tiempo en s (Infinity = no). */
  replaceTime: number;
  /** Tiempo de failover (s) si cae el primario o la instancia principal. */
  failoverTime: number;
  /** ¿Sobrevive a la caída de una AZ? */
  multiAz: boolean;
  /** Pieza con estado único (BD/caché): su caída es total hasta el failover. */
  stateful: boolean;
  /** Explicación corta de la estimación (se muestra en el inspector). */
  basis: string;
  /** Cuota o límite real relevante (texto). */
  quota?: string;
  /** Recurso fuera de la ruta del request (no recibe carga en la simulación). */
  passive?: boolean;
  /** Utilización objetivo del autoescalado (0‑1). Por defecto 0,7. */
  targetUtil?: number;
  /** Escalado por pasos: instancias que se agregan de golpe. */
  stepAdd?: number;
  /** Métrica con la que escala (para explicar los eventos). */
  scaleMetric?: 'cpu' | 'requests' | 'step' | 'capacity';
  /** Objetivo de peticiones por instancia (política por peticiones). */
  targetRequests?: number;
}

const INF = Number.POSITIVE_INFINITY;
const base = (p: Partial<SimProfile> & Pick<SimProfile, 'perInstance' | 'latency' | 'basis'>): SimProfile => ({
  instances: 1,
  maxInstances: 1,
  scale: 'none',
  scaleDelay: 0,
  replaceTime: INF,
  failoverTime: INF,
  multiAz: true,
  stateful: false,
  ...p,
});

/** Capacidad aproximada de RDS por clase de instancia (consultas simples/s). */
function rdsCapacity(cls: string): number {
  const c = cls.toLowerCase();
  // Azure: GP_Gen5_2 (vCores al final) o GP_Standard_D2s_v3 (vCPU en el tamaño)
  const vc = c.match(/_gen\d+_(\d+)$/) ?? c.match(/_[de](\d+)[a-z]*_v\d+$/);
  if (vc) return Number(vc[1]) * 750;
  const size = c.split('.').pop() ?? 'medium';
  const bySize: Record<string, number> = { micro: 300, small: 700, medium: 1500, large: 3000, xlarge: 6000, '2xlarge': 12000, '4xlarge': 24000, '8xlarge': 45000 };
  return bySize[size] ?? 1500;
}

/** Capacidad aproximada de EC2 por tipo (req/s de una app web típica). */
function ec2Capacity(type: string): number {
  // Azure: Standard_D2s_v5 → 2 vCPU ≈ 150 req/s por vCPU
  const az = type.match(/^standard_[a-z]+(\d+)/i);
  if (az) return Number(az[1]) * 150;
  const size = type.toLowerCase().split('.').pop() ?? 'medium';
  const bySize: Record<string, number> = { nano: 40, micro: 80, small: 150, medium: 300, large: 500, xlarge: 1000, '2xlarge': 2000, '4xlarge': 4000 };
  return bySize[size] ?? 300;
}

export function profileFor(node: ServiceNode): SimProfile {
  const p = node.data.props;
  const def = getService(node.data.serviceId);
  const num = (k: string, d: number) => (Number.isFinite(Number(p[k])) && p[k] !== '' && p[k] !== undefined ? Number(p[k]) : d);
  let prof: SimProfile;

  const az = azureProfile(node, num);
  if (az) prof = az;
  else switch (lidOf(node.data.serviceId)) {
    case 'user':
    case 'admin':
      prof = base({ perInstance: INF, latency: 0, basis: 'Origen del tráfico.' });
      break;
    case 'external':
      prof = base({ perInstance: 500, latency: 200, basis: 'Capacidad desconocida de un tercero; supuesto conservador de 500 req/s y 200 ms.', multiAz: true });
      break;
    case 'onprem':
      prof = base({ perInstance: 200, latency: 60, basis: 'Enlace VPN (~1.25 Gbps por túnel) y servidores propios: supuesto de 200 req/s.' });
      break;
    case 'route53':
      prof = base({ perInstance: INF, latency: 0, basis: 'DNS anycast global; no limita el throughput.' });
      break;
    case 'cloudfront':
      prof = base({ perInstance: 250000, latency: 15, basis: 'CDN global; 250.000 req/s por distribución (cuota por defecto).', quota: '250.000 req/s por distribución' });
      break;
    case 'waf':
    case 'shield':
      prof = base({ perInstance: INF, latency: 1, basis: 'Se evalúa en línea en CloudFront/ALB/API Gateway.' });
      break;
    case 'alb':
      prof = base({ perInstance: 100000, latency: 5, basis: 'Escala automáticamente; picos súbitos >10x pueden requerir pre‑calentamiento.' });
      break;
    case 'nlb':
      prof = base({ perInstance: 1_000_000, latency: 1, basis: 'Millones de conexiones por segundo.' });
      break;
    case 'apigw':
      prof = base({ perInstance: 10000, latency: 10, basis: 'Throttling por cuenta y región: 10.000 req/s (ráfaga 5.000). El exceso recibe HTTP 429.', quota: '10.000 req/s por cuenta/región' });
      break;
    case 'natgw':
    case 'igw':
    case 'vpce':
    case 'vpn':
      prof = base({ perInstance: INF, latency: 1, basis: 'Componente de red; no limita la simulación de requests.', passive: true });
      break;
    case 'lambda': {
      const dur = num('sim.durationMs', 120);
      const conc = num('sim.concurrency', 1000);
      prof = base({
        perInstance: (conc * 1000) / Math.max(1, dur),
        latency: dur,
        scale: 'instant',
        basis: `Concurrencia ${conc} (cuota por defecto de la cuenta) ÷ duración media ${dur} ms.`,
        quota: '1.000 ejecuciones concurrentes por cuenta/región',
      });
      break;
    }
    case 'ec2': {
      const count = Math.max(1, num('count', 2));
      const asg = !!p.autoscaling;
      const max = p.maxSize !== undefined ? Math.max(count, num('maxSize', count * 3)) : count * 3;
      prof = base({
        perInstance: ec2Capacity(String(p.instanceType ?? 't3.medium')),
        instances: count,
        maxInstances: asg ? max : count,
        targetUtil: num('targetCpu', 70) / 100,
        scale: asg ? 'asg' : 'none',
        scaleDelay: 180,
        latency: 40,
        replaceTime: asg ? 240 : INF,
        multiAz: count >= 2,
        basis: `${p.instanceType ?? 't3.medium'}: ~${ec2Capacity(String(p.instanceType ?? 't3.medium'))} req/s por instancia.${asg ? ` Auto Scaling ${count}→${max} al ${num('targetCpu', 70)}% de CPU: +instancias en ~3 min (detección + arranque).` : ' Sin Auto Scaling.'}`,
      });
      break;
    }
    case 'ecs': {
      const desired = Math.max(1, num('desired', 2));
      const cpu = num('cpu', 512);
      const auto = p['sim.autoscaling'] === undefined ? true : !!p['sim.autoscaling'];
      prof = base({
        perInstance: Math.round((cpu / 1024) * 400),
        instances: desired,
        maxInstances: auto ? Math.max(desired, num('maxTasks', desired * 4)) : desired,
        targetUtil: num('targetCpu', 70) / 100,
        scale: auto ? 'asg' : 'none',
        scaleDelay: 90,
        latency: 40,
        replaceTime: 60,
        multiAz: desired >= 2,
        basis: `${cpu} unidades de CPU por tarea → ~${Math.round((cpu / 1024) * 400)} req/s.${auto ? ' Service Auto Scaling: nuevas tareas en ~90 s.' : ''}`,
      });
      break;
    }
    case 'eks': {
      const n = Math.max(1, num('nodes', 3));
      prof = base({ perInstance: 400, instances: n, maxInstances: n * 3, scale: 'asg', scaleDelay: 150, latency: 40, replaceTime: 240, multiAz: n >= 2, basis: '~400 req/s por nodo.' });
      break;
    }
    case 'apprunner':
      prof = base({ perInstance: 100, instances: 1, maxInstances: 25, scale: 'asg', scaleDelay: 60, latency: 50, replaceTime: 60, basis: '~100 req/s por instancia (100 peticiones concurrentes).' });
      break;
    case 'ecr':
      prof = base({ perInstance: INF, latency: 0, basis: 'Solo se usa al desplegar.', passive: true });
      break;
    case 's3':
      prof = base({ perInstance: 30000, latency: 25, basis: '5.500 GET/s por prefijo; supuesto de varios prefijos (~30.000 req/s).', quota: '5.500 GET/s y 3.500 PUT/s por prefijo' });
      break;
    case 'efs':
      prof = base({ perInstance: 5000, latency: 5, basis: 'Modo elástico; supuesto de 5.000 ops/s.' });
      break;
    case 'rds': {
      const multi = !!p.multiAZ;
      const cap = rdsCapacity(String(p.instanceClass ?? 'db.t4g.medium'));
      prof = base({
        perInstance: cap,
        latency: 5,
        stateful: true,
        multiAz: multi,
        failoverTime: multi ? 90 : INF,
        basis: `${p.instanceClass ?? 'db.t4g.medium'}: ~${cap} consultas/s. ${multi ? 'Multi‑AZ: failover automático en 60‑120 s.' : 'Sin Multi‑AZ: si cae, hay que restaurar (minutos a horas).'}`,
      });
      break;
    }
    case 'aurora': {
      const replicas = Math.max(0, num('replicas', 1));
      const serverless = !!p.serverless;
      prof = base({
        perInstance: 3000,
        instances: 1 + replicas,
        maxInstances: serverless ? (1 + replicas) * 4 : 1 + replicas,
        scale: serverless ? 'serverless-db' : 'none',
        scaleDelay: 30,
        latency: 4,
        stateful: true,
        multiAz: replicas >= 1,
        failoverTime: replicas >= 1 ? 30 : 600,
        basis: `~3.000 consultas/s por instancia (escritor + ${replicas} réplica(s)).${serverless ? ' Serverless v2 escala la capacidad en segundos.' : ''} Failover ${replicas >= 1 ? '~30 s' : '~10 min (recrea la instancia)'}.`,
      });
      break;
    }
    case 'dynamodb': {
      const ondemand = p.billing !== 'PROVISIONED';
      prof = base({
        perInstance: ondemand ? 12000 : 1000,
        latency: 6,
        basis: ondemand ? 'On‑demand: una tabla nueva soporta ~12.000 lecturas/s al instante y se duplica con el tiempo.' : 'Provisionada: supuesto de 1.000 req/s; el exceso se throttlea.',
        quota: ondemand ? 'Duplica el pico previo cada 30 min' : 'RCU/WCU provisionadas',
      });
      break;
    }
    case 'elasticache': {
      const replicas = Math.max(0, num('replicas', 1));
      prof = base({
        perInstance: 50000,
        instances: 1 + replicas,
        maxInstances: 1 + replicas,
        latency: 1,
        stateful: true,
        multiAz: replicas >= 1,
        failoverTime: replicas >= 1 ? 30 : 300,
        basis: `~50.000 ops/s por nodo. ${replicas >= 1 ? 'Con réplica: failover ~30 s.' : 'Sin réplica: se reemplaza el nodo (~5 min) y la caché queda vacía.'}`,
      });
      break;
    }
    case 'documentdb': {
      const n = Math.max(1, num('instances', 2));
      prof = base({ perInstance: 2000, instances: n, maxInstances: n, latency: 6, stateful: true, multiAz: n >= 2, failoverTime: n >= 2 ? 30 : 600, basis: '~2.000 ops/s por instancia.' });
      break;
    }
    case 'opensearch': {
      const n = Math.max(1, num('instances', 2));
      prof = base({ perInstance: 500, instances: n, maxInstances: n, latency: 20, stateful: true, multiAz: n >= 2, failoverTime: n >= 2 ? 60 : 900, basis: '~500 búsquedas/s por nodo de datos.' });
      break;
    }
    case 'redshift':
      prof = base({ perInstance: 50, latency: 500, stateful: true, multiAz: false, failoverTime: 900, basis: 'Data warehouse: ~50 consultas concurrentes/s; no es para tráfico transaccional.' });
      break;
    case 'sqs':
      prof = base({ perInstance: p.fifo ? 3000 : INF, latency: 10, basis: p.fifo ? 'FIFO: 3.000 mensajes/s con lotes.' : 'Estándar: throughput prácticamente ilimitado.', quota: p.fifo ? '3.000 msg/s (FIFO con batching)' : undefined });
      break;
    case 'sns':
      prof = base({ perInstance: 30000, latency: 20, basis: 'Publish: ~30.000 msg/s en us‑east‑1.', quota: '30.000 Publish/s (us‑east‑1)' });
      break;
    case 'eventbridge':
      prof = base({ perInstance: 10000, latency: 20, basis: 'PutEvents: 10.000 eventos/s en us‑east‑1.', quota: '10.000 PutEvents/s (us‑east‑1)' });
      break;
    case 'stepfunctions':
      prof = base({ perInstance: p.type === 'EXPRESS' ? 6000 : 1300, latency: 50, basis: p.type === 'EXPRESS' ? 'Express: ~6.000 inicios/s.' : 'Standard: StartExecution ~1.300/s (bucket por defecto).' });
      break;
    case 'kinesis':
      prof = base({ perInstance: 4000, latency: 15, basis: 'On‑demand: 4.000 registros/s iniciales (4 MB/s).' });
      break;
    case 'firehose':
      prof = base({ perInstance: 2000, latency: 60, basis: '~2.000 registros/s por stream (cuota por defecto en varias regiones).' });
      break;
    case 'msk': {
      const b = Math.max(1, num('brokers', 3));
      prof = base({ perInstance: 10000, instances: b, maxInstances: b, latency: 5, stateful: true, multiAz: b >= 2, failoverTime: 60, basis: '~10.000 msg/s por broker.' });
      break;
    }
    case 'cognito':
      prof = base({ perInstance: 120, latency: 80, basis: 'Categoría UserAuthentication: 120 req/s por defecto. Los picos de login son el cuello de botella típico.', quota: '120 req/s (UserAuthentication)' });
      break;
    case 'secrets':
      prof = base({ perInstance: 10000, latency: 15, basis: 'GetSecretValue: 10.000 req/s. Las apps deberían cachear el secreto.' });
      break;
    case 'kms':
      prof = base({ perInstance: 10000, latency: 5, basis: 'Operaciones criptográficas: 5.500‑50.000/s según región.' });
      break;
    case 'bedrock':
      prof = base({ perInstance: 20, latency: 1500, basis: 'On‑demand: cuotas de tokens/min por modelo; supuesto de ~20 req/s y 1,5 s por respuesta.', quota: 'Tokens por minuto por modelo' });
      break;
    case 'sagemaker':
      prof = base({ perInstance: 200, latency: 100, basis: '~200 inferencias/s por instancia del endpoint.' });
      break;
    case 'beanstalk':
      prof = base({ perInstance: ec2Capacity(String(p.instanceType ?? 't3.medium')), instances: 2, maxInstances: 6, scale: 'asg', scaleDelay: 180, latency: 40, replaceTime: 240, multiAz: true, basis: `${p.instanceType ?? 't3.medium'}: ~${ec2Capacity(String(p.instanceType ?? 't3.medium'))} req/s por instancia.` });
      break;
    case 'lightsail': {
      const per = String(p.bundle ?? '').startsWith('nano') ? 40 : String(p.bundle ?? '').startsWith('medium') ? 300 : String(p.bundle ?? '').startsWith('large') ? 500 : 150;
      prof = base({ perInstance: per, latency: 40, multiAz: false, replaceTime: INF, basis: `Una instancia de precio fijo: ~${per} req/s (supuesto). No escala ni se reemplaza sola.` });
      break;
    }
    case 'globalaccelerator':
      prof = base({ perInstance: INF, latency: 5, basis: 'Red global de AWS con IPs anycast; no limita el throughput.' });
      break;
    case 'appsync':
      prof = base({ perInstance: 2000, latency: 20, basis: 'GraphQL administrado; supuesto de ~2.000 req/s (la cuota real por API es ajustable).', quota: 'Peticiones por segundo por API (ajustable)' });
      break;
    case 'iotcore':
      prof = base({ perInstance: 20000, latency: 20, basis: 'Mensajes MQTT; supuesto de ~20.000 msg/s por cuenta (cuotas ajustables).' });
      break;
    case 'transferfamily':
      prof = base({ perInstance: 100, latency: 200, basis: 'Sesiones SFTP concurrentes: supuesto de ~100 operaciones/s.' });
      break;
    case 'mq': {
      const multi = p.multiAZ !== false;
      prof = base({ perInstance: 5000, latency: 10, stateful: true, multiAz: multi, failoverTime: multi ? 60 : INF, basis: `Broker mq.m5.large: ~5.000 msg/s (supuesto). ${multi ? 'Multi‑AZ: failover ~1 min.' : 'Una sola instancia: si cae, se detiene la mensajería.'}` });
      break;
    }
    case 'neptune': {
      const n = Math.max(1, num('instances', 2));
      prof = base({ perInstance: 1000, instances: n, maxInstances: n, latency: 10, stateful: true, multiAz: n >= 2, failoverTime: n >= 2 ? 30 : 600, basis: '~1.000 consultas de grafo/s por instancia (supuesto).' });
      break;
    }
    case 'memorydb': {
      const r = Math.max(0, num('replicas', 1));
      const sh = Math.max(1, num('shards', 1));
      prof = base({ perInstance: 50000, instances: sh * (1 + r), maxInstances: sh * (1 + r), latency: 2, stateful: true, multiAz: r >= 1, failoverTime: r >= 1 ? 20 : 300, basis: `~50.000 ops/s por nodo; ${sh} shard(s) con ${r} réplica(s). Durable: no pierde datos al reiniciar.` });
      break;
    }
    case 'dax': {
      const n = Math.max(1, num('nodes', 3));
      prof = base({ perInstance: 100000, instances: n, maxInstances: n, latency: 1, stateful: true, multiAz: n >= 2, failoverTime: 30, basis: '~100.000 lecturas/s por nodo desde caché (microsegundos).' });
      break;
    }
    case 'keyspaces':
      prof = base({ perInstance: 10000, latency: 8, basis: 'On‑demand: supuesto de ~10.000 req/s iniciales.' });
      break;
    case 'timestream':
      prof = base({ perInstance: 5000, latency: 20, basis: 'Ingesta de series de tiempo: supuesto de ~5.000 escrituras/s.' });
      break;
    case 'fsx':
      prof = base({ perInstance: 10000, latency: 3, stateful: true, multiAz: true, failoverTime: 60, basis: 'Sistema de archivos administrado: supuesto de ~10.000 ops/s.' });
      break;
    case 'ses':
      prof = base({ perInstance: 14, latency: 100, basis: 'Envío de correo: la cuota inicial típica es baja (decenas por segundo) y se amplía con el historial de la cuenta.', quota: 'Cuota de envío por segundo de la cuenta' });
      break;
    case 'kendra':
      prof = base({ perInstance: 10, latency: 400, basis: 'Búsqueda empresarial: supuesto de ~10 consultas/s por unidad de consulta.' });
      break;
    case 'rekognition':
    case 'textract':
    case 'comprehend':
    case 'transcribe':
    case 'translate':
    case 'polly':
      prof = base({ perInstance: 50, latency: 600, basis: 'API de IA administrada: supuesto de ~50 req/s (cuotas por API y región) y ~0,6 s por respuesta.', quota: 'Transacciones por segundo por API' });
      break;
    default:
      prof = base({ perInstance: INF, latency: 0, basis: `${def.name} queda fuera de la ruta del request en la simulación.`, passive: true });
  }

  applyScaling(node, prof);

  // Overrides manuales desde el inspector
  const capOv = Number(p['sim.capacity']);
  if (Number.isFinite(capOv) && capOv > 0) {
    prof.perInstance = capOv;
    prof.basis = `Capacidad definida manualmente: ${capOv} req/s por instancia.`;
  }
  return prof;
}

/** Aplica la configuración de escalado del inspector (sección «Escalado») al perfil. */
function applyScaling(node: ServiceNode, prof: SimProfile) {
  const sc = scalingOf(node);
  if (!sc) return;
  const first = prof.basis.split(/(?<=\.)\s/)[0];
  switch (sc.kind) {
    case 'instances':
    case 'tasks':
    case 'nodes':
    case 'app': {
      const grows = sc.policy === 'cpu' || sc.policy === 'requests' || sc.policy === 'step';
      prof.instances = Math.max(1, sc.desired);
      prof.maxInstances = grows ? Math.max(prof.instances, sc.max) : prof.instances;
      prof.scale = grows ? 'asg' : 'none';
      prof.scaleDelay = sc.detection + sc.warmup;
      prof.scaleMetric = sc.policy === 'requests' ? 'requests' : sc.policy === 'step' ? 'step' : 'cpu';
      prof.targetUtil =
        sc.policy === 'requests' ? (Number.isFinite(prof.perInstance) && prof.perInstance > 0 ? sc.targetRequests / prof.perInstance : 0.7)
        : sc.policy === 'step' ? sc.stepThreshold / 100
        : sc.targetCpu / 100;
      prof.targetRequests = sc.policy === 'requests' ? sc.targetRequests : undefined;
      prof.stepAdd = sc.policy === 'step' ? sc.stepAdd : undefined;
      if (sc.kind === 'instances') prof.replaceTime = sc.policy === 'manual' ? INF : 240;
      prof.multiAz = prof.instances >= 2;
      prof.basis = `${first} ${describeScaling(node, prof.perInstance)}`;
      break;
    }
    case 'functions':
      if (sc.reserved) {
        prof.perInstance = (sc.reserved * 1000) / Math.max(1, prof.latency);
        prof.quota = `Concurrencia reservada: ${sc.reserved}`;
      }
      prof.basis = `${prof.basis} ${describeScaling(node)}`;
      break;
    case 'aurora': {
      const nInst = 1 + (sc.replicas ?? 0);
      if (sc.serverless) {
        prof.perInstance = 750;
        prof.instances = Math.max(1, Math.round((sc.minAcu ?? 2) * nInst));
        prof.maxInstances = Math.max(prof.instances, Math.round((sc.maxAcu ?? 16) * nInst));
        prof.scale = 'serverless-db';
        prof.scaleDelay = 15;
        prof.scaleMetric = 'capacity';
        prof.basis = `~750 consultas/s por ACU. ${describeScaling(node)} Failover ${nInst > 1 ? '~30 s' : '~10 min (recrea la instancia)'}.`;
      } else {
        prof.perInstance = 3000;
        prof.instances = nInst;
        prof.maxInstances = nInst;
        prof.scale = 'none';
        prof.basis = `~3.000 consultas/s por instancia. ${describeScaling(node)}`;
      }
      prof.multiAz = nInst >= 2;
      prof.failoverTime = nInst >= 2 ? 30 : 600;
      break;
    }
    case 'nosql':
      if (node.data.serviceId === 'dynamodb' || lidOf(node.data.serviceId) === 'dynamodb') {
        if (node.data.serviceId.startsWith('az-')) break;
        if (sc.billing === 'PROVISIONED') {
          prof.perInstance = sc.rcu ?? 1000;
          prof.instances = 1;
          prof.maxInstances = sc.policy === 'cpu' ? Math.max(1, Math.ceil((sc.maxRcu ?? 4000) / (sc.rcu ?? 1000))) : 1;
          prof.scale = sc.policy === 'cpu' ? 'asg' : 'none';
          prof.scaleDelay = 300;
          prof.scaleMetric = 'capacity';
          prof.quota = `${sc.rcu} RCU provisionadas`;
          prof.basis = describeScaling(node);
        }
      }
      break;
    case 'throttle':
      if (node.data.serviceId === 'apigw') {
        prof.perInstance = sc.rateLimit ?? 10000;
        prof.quota = `Throttling: ${sc.rateLimit} req/s (ráfaga ${sc.burstLimit})`;
        prof.basis = `${describeScaling(node)} El límite de la cuenta es 10.000 req/s.`;
      } else if (node.data.props.rateLimit !== undefined) {
        prof.perInstance = Math.min(prof.perInstance, sc.rateLimit ?? prof.perInstance);
        prof.basis = `${prof.basis} Política rate-limit: ${sc.rateLimit} req/s.`;
      }
      break;
  }
}

/** Perfiles propios de Azure (cuando difieren del equivalente de AWS). */
function azureProfile(node: ServiceNode, num: (k: string, d: number) => number): SimProfile | null {
  const p = node.data.props;
  switch (node.data.serviceId) {
    case 'az-frontdoor':
      return base({ perInstance: 250000, latency: 15, basis: 'CDN global de Microsoft; sin límite práctico de req/s para una aplicación típica.' });
    case 'az-appgw':
      return base({ perInstance: 50000, latency: 6, basis: 'Application Gateway v2 autoescala por unidades de capacidad; supuesto de ~50.000 req/s.', quota: 'Máximo de instancias de autoescalado configurado' });
    case 'az-apim': {
      const tier = String(p.type ?? 'Standard v2');
      const cap = tier === 'Consumption' ? 2000 : tier === 'Basic v2' ? 1000 : tier === 'Premium v2' ? 5000 : 2500;
      return base({ perInstance: cap, latency: 12, basis: `API Management ${tier}: ~${cap} req/s por unidad (estimación de Microsoft; varía según las políticas). El exceso responde 429.`, quota: `${tier}: capacidad por unidad` });
    }
    case 'az-functions': {
      const dur = num('sim.durationMs', 120);
      const conc = num('sim.concurrency', 1600);
      return base({ perInstance: (conc * 1000) / Math.max(1, dur), latency: dur, scale: 'instant', basis: `Flex Consumption: hasta 100 instancias × 16 requests concurrentes (${conc}) ÷ duración media ${dur} ms.`, quota: '100 instancias por app (máximo por defecto)' });
    }
    case 'az-appservice': {
      const n = Math.max(1, num('instances', 2));
      const per = { B1: 100, S1: 200, P1v3: 400, P2v3: 800, P3v3: 1600 }[String(p.sku ?? 'P1v3')] ?? 400;
      return base({ perInstance: per, instances: n, maxInstances: Math.max(n, 10), scale: 'asg', scaleDelay: 240, latency: 45, replaceTime: 120, multiAz: n >= 2, basis: `Plan ${p.sku ?? 'P1v3'}: ~${per} req/s por instancia.` });
    }
    case 'az-containerapps': {
      const desired = Math.max(1, num('desired', 2));
      const cpu = num('cpu', 512);
      const per = Math.round((cpu / 1024) * 400);
      return base({ perInstance: per, instances: desired, maxInstances: Math.max(desired, num('maxTasks', Math.max(desired * 5, 10))), targetUtil: num('targetCpu', 70) / 100, scale: 'asg', scaleDelay: 45, latency: 40, replaceTime: 30, multiAz: desired >= 2, basis: `${cpu / 1024} vCPU por réplica → ~${per} req/s. Escalado HTTP con KEDA en ~45 s.` });
    }
    case 'az-cosmos': {
      const mode = String(p.billing ?? 'Autoscale');
      const ru = mode === 'Serverless' ? 5000 : mode === 'Provisioned' ? num('ru', 400) : num('ru', 4000);
      return base({ perInstance: Math.round(ru / 3), latency: 6, basis: `${mode}: ${ru} RU/s ÷ ~3 RU por operación (mezcla de lecturas y escrituras) ≈ ${Math.round(ru / 3)} ops/s. El exceso responde 429.`, quota: `${ru} RU/s` });
    }
    case 'az-sql':
    case 'az-postgres': {
      const multi = !!p.multiAZ;
      const cap = rdsCapacity(String(p.instanceClass ?? 'GP_Gen5_2'));
      const sql = node.data.serviceId === 'az-sql';
      return base({
        perInstance: cap,
        latency: 5,
        stateful: true,
        multiAz: multi,
        failoverTime: multi ? 30 : sql ? 120 : 300,
        basis: `${p.instanceClass}: ~${cap} consultas/s. ${multi ? 'Redundancia de zona: failover automático en segundos.' : sql ? 'Alta disponibilidad local: se recupera en minutos, pero no sobrevive a la caída de una zona.' : 'Sin HA: se reaprovisiona en ~5 min y no sobrevive a la caída de una zona.'}`,
      });
    }
    case 'az-redis': {
      const replicas = Math.max(0, num('replicas', 1));
      const premium = String(p.nodeType ?? '').startsWith('Premium');
      return base({ perInstance: premium ? 80000 : 40000, instances: 1 + replicas, maxInstances: 1 + replicas, latency: 1, stateful: true, multiAz: replicas >= 1 && premium, failoverTime: replicas >= 1 ? 30 : 300, basis: `${p.nodeType}: ~${premium ? '80.000' : '40.000'} ops/s. ${replicas >= 1 ? 'Réplica con failover en ~30 s' : 'Sin réplica (Basic): sin SLA de disponibilidad'}${premium ? '' : '; la redundancia de zona requiere Premium'}.` });
    }
    case 'az-servicebus':
      return base({ perInstance: 2000, latency: 15, basis: 'Service Bus Standard: ~2.000 mensajes/s (variable, sin capacidad reservada). Premium reserva capacidad por Messaging Unit.', quota: 'Throughput compartido (Standard)' });
    case 'az-servicebus-topic':
      return base({ perInstance: 2000, latency: 20, basis: 'Service Bus Standard: ~2.000 mensajes/s.' });
    case 'az-eventgrid':
      return base({ perInstance: 5000, latency: 20, basis: 'Tópico personalizado: 5.000 eventos/s de publicación.', quota: '5.000 eventos/s por tópico' });
    case 'az-eventhubs': {
      const units = Math.max(1, num('units', 2));
      const premium = p.mode === 'Premium';
      return base({ perInstance: premium ? units * 10000 : units * 1000, latency: 15, basis: premium ? `${units} Processing Units ≈ ${units * 10000} eventos/s.` : `${units} Throughput Units × 1.000 eventos/s de ingesta.`, quota: premium ? 'Processing Units' : '1.000 eventos/s por TU' });
    }
    case 'az-entra':
      return base({ perInstance: 200, latency: 90, basis: 'Límites de servicio de Entra para emisión de tokens; supuesto de ~200 req/s. Los picos de login son el cuello de botella típico.', quota: 'Límites de throttling del tenant' });
    case 'az-keyvault':
      return base({ perInstance: 400, latency: 15, basis: 'Key Vault: 4.000 transacciones de secretos cada 10 s por vault (~400/s). Cachea los secretos en la aplicación.', quota: '4.000 transacciones / 10 s' });
    case 'az-openai':
      return base({ perInstance: 15, latency: 1500, basis: 'Cuota de tokens por minuto (TPM) del deployment; supuesto de ~15 req/s y 1,5 s por respuesta.', quota: 'TPM / RPM del deployment' });
    case 'az-blob':
      return base({ perInstance: 20000, latency: 25, basis: 'Cuenta de almacenamiento: ~20.000 req/s (objetivo de escalabilidad estándar).', quota: '20.000 req/s por cuenta' });
    default:
      return null;
  }
}

export function fmtRps(v: number): string {
  if (!Number.isFinite(v)) return '∞';
  if (v === 0) return '0';
  if (v >= 1_000_000) return `${(v / 1_000_000).toFixed(1)}M`;
  if (v >= 10_000) return `${Math.round(v / 1000)}k`;
  if (v >= 1000) return `${(v / 1000).toFixed(1)}k`;
  if (v >= 10) return String(Math.round(v));
  return v.toFixed(1);
}
