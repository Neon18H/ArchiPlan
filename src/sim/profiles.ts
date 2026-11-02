/**
 * Perfiles de simulación por servicio.
 *
 * IMPORTANTE: son ESTIMACIONES de orden de magnitud basadas en cuotas por defecto de AWS
 * y cargas web típicas. No reemplazan una prueba de carga real. Cada pieza permite
 * sobrescribir su capacidad desde el inspector (props `sim.capacity` y `sim.instances`).
 */
import { getService } from '../catalog/catalog';
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
  const size = c.split('.').pop() ?? 'medium';
  const bySize: Record<string, number> = { micro: 300, small: 700, medium: 1500, large: 3000, xlarge: 6000, '2xlarge': 12000, '4xlarge': 24000, '8xlarge': 45000 };
  return bySize[size] ?? 1500;
}

/** Capacidad aproximada de EC2 por tipo (req/s de una app web típica). */
function ec2Capacity(type: string): number {
  const size = type.toLowerCase().split('.').pop() ?? 'medium';
  const bySize: Record<string, number> = { nano: 40, micro: 80, small: 150, medium: 300, large: 500, xlarge: 1000, '2xlarge': 2000, '4xlarge': 4000 };
  return bySize[size] ?? 300;
}

export function profileFor(node: ServiceNode): SimProfile {
  const p = node.data.props;
  const def = getService(node.data.serviceId);
  const num = (k: string, d: number) => (Number.isFinite(Number(p[k])) && p[k] !== '' && p[k] !== undefined ? Number(p[k]) : d);
  let prof: SimProfile;

  switch (node.data.serviceId) {
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
      prof = base({
        perInstance: ec2Capacity(String(p.instanceType ?? 't3.medium')),
        instances: count,
        maxInstances: asg ? count * 3 : count,
        scale: asg ? 'asg' : 'none',
        scaleDelay: 180,
        latency: 40,
        replaceTime: asg ? 240 : INF,
        multiAz: count >= 2,
        basis: `${p.instanceType ?? 't3.medium'}: ~${ec2Capacity(String(p.instanceType ?? 't3.medium'))} req/s por instancia.${asg ? ' Auto Scaling: +instancias en ~3 min (detección + arranque).' : ' Sin Auto Scaling.'}`,
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
        maxInstances: auto ? desired * 4 : desired,
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
      prof = base({ perInstance: 400, instances: n, maxInstances: n * 3, scale: 'asg', scaleDelay: 150, latency: 40, replaceTime: 240, multiAz: n >= 2, basis: '~400 req/s por nodo; Cluster Autoscaler agrega nodos en ~2‑3 min.' });
      break;
    }
    case 'apprunner':
      prof = base({ perInstance: 100, instances: 1, maxInstances: 25, scale: 'asg', scaleDelay: 60, latency: 50, replaceTime: 60, basis: '100 requests concurrentes por instancia, hasta 25 instancias.' });
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
    default:
      prof = base({ perInstance: INF, latency: 0, basis: `${def.name} queda fuera de la ruta del request en la simulación.`, passive: true });
  }

  // Overrides manuales desde el inspector
  const capOv = Number(p['sim.capacity']);
  if (Number.isFinite(capOv) && capOv > 0) {
    prof.perInstance = capOv;
    prof.basis = `Capacidad definida manualmente: ${capOv} req/s por instancia.`;
  }
  return prof;
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
