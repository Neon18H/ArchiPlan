/**
 * Escalado configurable: cómo crece (o no) cada pieza. Lo usan el inspector, la
 * simulación, la validación, el modelo de amenazas y el Terraform.
 *
 * Todo se guarda en las propiedades de la pieza (node.data.props) para que viaje
 * con el proyecto y con la conversión AWS ⇄ Azure.
 */
import { lid } from '../catalog/catalog';
import type { PropValue, ServiceNode } from '../types';

export type ScalePolicy = 'manual' | 'fixed' | 'cpu' | 'requests' | 'step';

export type ScalingKind =
  /** EC2 / VMSS: grupo de instancias. */
  | 'instances'
  /** ECS / Container Apps: tareas o réplicas de un servicio. */
  | 'tasks'
  /** EKS / AKS: nodos del clúster. */
  | 'nodes'
  /** App Runner / App Service: instancias administradas. */
  | 'app'
  /** Lambda / Functions: concurrencia. */
  | 'functions'
  /** Aurora: réplicas y capacidad serverless. */
  | 'aurora'
  /** DynamoDB / Cosmos DB: modo de capacidad. */
  | 'nosql'
  /** API Gateway / APIM: throttling. */
  | 'throttle';

export function scalingKind(n: ServiceNode): ScalingKind | null {
  switch (lid(n)) {
    case 'ec2':
    case 'beanstalk':
      return 'instances';
    case 'ecs':
      return 'tasks';
    case 'eks':
      return 'nodes';
    case 'apprunner':
      return 'app';
    case 'lambda':
      return 'functions';
    case 'aurora':
      return 'aurora';
    case 'dynamodb':
      return 'nosql';
    case 'apigw':
      return 'throttle';
    default:
      return null;
  }
}

/** Claves de propiedades que se editan en la sección «Escalado» (no en «Configuración»). */
export const SCALING_KEYS = new Set([
  'count',
  'desired',
  'nodes',
  'instances',
  'autoscaling',
  'scalePolicy',
  'minSize',
  'maxSize',
  'maxTasks',
  'targetCpu',
  'targetRequests',
  'stepThreshold',
  'stepAdd',
  'warmup',
  'serverless',
  'replicas',
  'minAcu',
  'maxAcu',
  'billing',
  'ru',
  'rcu',
  'wcu',
  'maxRcu',
  'reservedConcurrency',
  'provisionedConcurrency',
  'rateLimit',
  'burstLimit',
  'sim.autoscaling',
]);

export interface Scaling {
  kind: ScalingKind;
  policy: ScalePolicy;
  /** Tamaño inicial (instancias, tareas, nodos…). */
  desired: number;
  min: number;
  max: number;
  /** % de CPU objetivo (política cpu) o umbral (política por pasos). */
  targetCpu: number;
  /** Peticiones por instancia y segundo (política requests). */
  targetRequests: number;
  stepThreshold: number;
  stepAdd: number;
  /** Segundos que tarda una instancia nueva en estar lista (arranque + health checks). */
  warmup: number;
  /** Segundos que tarda en detectar que hay que escalar (alarma de CloudWatch / Azure Monitor). */
  detection: number;
  // Específicos
  serverless?: boolean;
  replicas?: number;
  minAcu?: number;
  maxAcu?: number;
  billing?: string;
  rcu?: number;
  maxRcu?: number;
  ru?: number;
  reserved?: number;
  provisioned?: number;
  rateLimit?: number;
  burstLimit?: number;
}

const num = (p: Record<string, PropValue>, k: string, d: number) => (p[k] !== undefined && p[k] !== '' && Number.isFinite(Number(p[k])) ? Number(p[k]) : d);

const WARMUP: Record<ScalingKind, number> = { instances: 120, tasks: 30, nodes: 90, app: 60, functions: 0, aurora: 15, nosql: 120, throttle: 0 };

export function scalingOf(n: ServiceNode): Scaling | null {
  const kind = scalingKind(n);
  if (!kind) return null;
  const p = n.data.props;
  const azure = n.data.serviceId.startsWith('az-');
  const legacyPolicy = (): ScalePolicy => {
    if (kind === 'instances') return p.autoscaling === false ? 'manual' : 'cpu';
    if (kind === 'tasks') return p['sim.autoscaling'] === false ? 'fixed' : azure ? 'requests' : 'cpu';
    if (kind === 'nodes') return 'cpu';
    if (kind === 'app') return 'requests';
    return 'fixed';
  };
  const policy = (['manual', 'fixed', 'cpu', 'requests', 'step'].includes(String(p.scalePolicy)) ? String(p.scalePolicy) : legacyPolicy()) as ScalePolicy;
  const desiredKey = kind === 'instances' ? 'count' : kind === 'tasks' ? 'desired' : kind === 'nodes' ? 'nodes' : 'instances';
  const desired = Math.max(kind === 'tasks' ? 0 : 1, num(p, desiredKey, kind === 'nodes' ? 3 : kind === 'app' ? (azure ? 2 : 1) : 2));
  const defMax = kind === 'instances' ? desired * 3 : kind === 'tasks' ? (azure ? Math.max(desired * 5, 10) : desired * 4) : kind === 'nodes' ? desired * 3 : kind === 'app' ? (azure ? 10 : 25) : desired;
  const s: Scaling = {
    kind,
    policy,
    desired,
    min: Math.min(desired, num(p, 'minSize', kind === 'tasks' ? Math.min(desired, 1) : desired)),
    max: Math.max(desired, num(p, 'maxSize', num(p, 'maxTasks', defMax))),
    targetCpu: num(p, 'targetCpu', 60),
    targetRequests: num(p, 'targetRequests', kind === 'app' ? (azure ? 100 : 80) : kind === 'tasks' && azure ? 50 : 200),
    stepThreshold: num(p, 'stepThreshold', 70),
    stepAdd: Math.max(1, num(p, 'stepAdd', 2)),
    warmup: num(p, 'warmup', WARMUP[kind]),
    detection: kind === 'nodes' ? 30 : azure && kind === 'tasks' ? 15 : 60,
  };
  if (kind === 'aurora') {
    s.serverless = p.serverless !== false;
    s.replicas = Math.max(0, num(p, 'replicas', 1));
    s.minAcu = Math.max(0.5, num(p, 'minAcu', 2));
    s.maxAcu = Math.max(s.minAcu, num(p, 'maxAcu', 16));
    s.policy = s.serverless ? 'cpu' : 'fixed';
    s.detection = 5;
  }
  if (kind === 'nosql') {
    s.billing = String(p.billing ?? (azure ? 'Autoscale' : 'PAY_PER_REQUEST'));
    s.rcu = Math.max(1, num(p, 'rcu', 1000));
    s.maxRcu = Math.max(s.rcu, num(p, 'maxRcu', s.rcu * 4));
    s.ru = num(p, 'ru', 4000);
    s.policy = s.billing === 'PROVISIONED' ? (p.autoscaling === false ? 'fixed' : 'cpu') : 'fixed';
  }
  if (kind === 'functions') {
    s.reserved = Math.max(0, num(p, 'reservedConcurrency', 0));
    s.provisioned = Math.max(0, num(p, 'provisionedConcurrency', 0));
  }
  if (kind === 'throttle') {
    s.rateLimit = Math.max(1, num(p, 'rateLimit', 10000));
    s.burstLimit = Math.max(1, num(p, 'burstLimit', 5000));
  }
  return s;
}

/** Qué políticas tiene sentido ofrecer para cada tipo. */
export function policiesFor(kind: ScalingKind, behindLb: boolean): { id: ScalePolicy; label: string; help: string }[] {
  const out: { id: ScalePolicy; label: string; help: string }[] = [];
  if (kind === 'instances') out.push({ id: 'manual', label: 'Sin ASG', help: 'Instancias sueltas: si una cae, nadie la reemplaza.' });
  if (['instances', 'tasks', 'nodes', 'app'].includes(kind)) {
    out.push({ id: 'fixed', label: 'Tamaño fijo', help: 'Siempre la misma cantidad; reemplaza las que fallan, pero no crece con la carga.' });
    out.push({ id: 'cpu', label: kind === 'nodes' ? 'Autoscaler' : 'Por CPU', help: kind === 'nodes' ? 'Cluster Autoscaler / Karpenter agrega nodos cuando hay pods pendientes.' : 'Target tracking: mantiene la CPU promedio cerca del objetivo.' });
    if (kind !== 'nodes') out.push({ id: 'requests', label: 'Por peticiones', help: behindLb || kind === 'app' ? 'Mantiene las peticiones por instancia cerca del objetivo.' : 'Requiere un balanceador delante (métrica de peticiones por target).' });
    if (kind === 'instances' || kind === 'tasks') out.push({ id: 'step', label: 'Por pasos', help: 'Cuando la CPU supera el umbral, agrega un bloque fijo de instancias.' });
  }
  return out;
}

/** Explicación en una frase de cómo escala la pieza (inspector, simulación, documento, IA). */
export function describeScaling(n: ServiceNode, perInstance?: number): string {
  const s = scalingOf(n);
  if (!s) return '';
  const unit = s.kind === 'tasks' ? (n.data.serviceId.startsWith('az-') ? 'réplicas' : 'tareas') : s.kind === 'nodes' ? 'nodos' : 'instancias';
  const ready = `cada una tarda ~${Math.round((s.detection + s.warmup) / 10) * 10} s en estar lista`;
  switch (s.kind) {
    case 'functions':
      return s.reserved ? `Hasta ${s.reserved} ejecuciones simultáneas (concurrencia reservada)${s.provisioned ? `; ${s.provisioned} siempre calientes` : ''}.` : `Escala sola hasta la concurrencia de la cuenta${s.provisioned ? `; ${s.provisioned} ejecuciones siempre calientes (sin arranque en frío)` : ''}.`;
    case 'aurora':
      return s.serverless ? `Serverless v2 entre ${s.minAcu} y ${s.maxAcu} ACU por instancia (escritor + ${s.replicas} réplica${s.replicas === 1 ? '' : 's'}); ajusta la capacidad en segundos.` : `Capacidad fija: escritor + ${s.replicas} réplica${s.replicas === 1 ? '' : 's'} de lectura.`;
    case 'nosql':
      if (n.data.serviceId === 'az-cosmos') return s.billing === 'Serverless' ? 'Serverless: paga por operación, hasta ~5.000 RU/s.' : s.billing === 'Provisioned' ? `${s.ru} RU/s fijas; el exceso responde 429.` : `Autoscale hasta ${s.ru} RU/s (baja al 10 % cuando no hay carga).`;
      return s.billing === 'PROVISIONED' ? (s.policy === 'fixed' ? `${s.rcu} unidades de lectura fijas; el exceso se throttlea.` : `${s.rcu} unidades de lectura, auto scaling hasta ${s.maxRcu} (tarda minutos).`) : 'On‑demand: absorbe picos al instante (hasta el doble del pico previo).';
    case 'throttle':
      return `Acepta ${s.rateLimit} req/s (ráfagas de ${s.burstLimit}); el exceso recibe 429.`;
  }
  const start = `Empieza con ${s.desired} ${unit}`;
  switch (s.policy) {
    case 'manual':
      return `${start} sueltas, sin Auto Scaling Group: no crece y una instancia caída no se reemplaza.`;
    case 'fixed':
      return `${start} fijas: reemplaza las que fallan, pero no crece con la carga.`;
    case 'cpu':
      return s.kind === 'nodes' ? `${start}; el autoscaler agrega nodos hasta ${s.max} cuando faltan recursos (${ready}).` : `${start}; si la CPU pasa de ${s.targetCpu} % agrega ${unit} hasta ${s.max} (${ready}).`;
    case 'requests': {
      const sat = perInstance && Number.isFinite(perInstance) && s.targetRequests > perInstance ? ` Ojo: cada una se satura con ~${Math.round(perInstance)} req/s, antes de llegar al objetivo.` : '';
      return `${start}; si cada una recibe más de ${s.targetRequests} req/s agrega ${unit} hasta ${s.max} (${ready}).${sat}`;
    }
    case 'step':
      return `${start}; cuando la CPU pasa de ${s.stepThreshold} % agrega ${s.stepAdd} de golpe, hasta ${s.max} (${ready}).`;
  }
}

/** Problemas de configuración del escalado (los usa la validación). */
export function scalingProblems(n: ServiceNode): { severity: 'error' | 'warn'; title: string; detail: string; props?: Record<string, PropValue> }[] {
  const s = scalingOf(n);
  if (!s) return [];
  const out: { severity: 'error' | 'warn'; title: string; detail: string; props?: Record<string, PropValue> }[] = [];
  const name = n.data.label;
  if (['instances', 'tasks', 'nodes', 'app'].includes(s.kind)) {
    const p = n.data.props;
    const rawMin = p.minSize !== undefined ? Number(p.minSize) : s.min;
    const rawMax = p.maxSize !== undefined ? Number(p.maxSize) : p.maxTasks !== undefined ? Number(p.maxTasks) : s.max;
    if (rawMin > s.desired || s.desired > rawMax)
      out.push({ severity: 'error', title: `${name}: el escalado no cuadra`, detail: `Debe cumplirse mínimo ≤ inicial ≤ máximo (hoy ${rawMin} ≤ ${s.desired} ≤ ${rawMax}). La nube rechaza esta configuración.`, props: { minSize: Math.min(rawMin, s.desired), maxSize: Math.max(rawMax, s.desired) } });
    else if (['cpu', 'requests', 'step'].includes(s.policy) && s.max <= s.desired)
      out.push({ severity: 'warn', title: `${name}: el máximo es igual al tamaño inicial`, detail: 'Tiene autoescalado, pero no puede crecer ante un pico.', props: { maxSize: s.desired * 3 } });
    if (s.policy === 'cpu' && (s.targetCpu < 20 || s.targetCpu > 90)) out.push({ severity: 'warn', title: `${name}: CPU objetivo de ${s.targetCpu} %`, detail: s.targetCpu > 90 ? 'Con un objetivo tan alto escala cuando ya está saturado.' : 'Con un objetivo tan bajo mantiene muchas instancias ociosas (costo).', props: { targetCpu: 60 } });
  }
  if (s.kind === 'aurora' && s.serverless && (s.maxAcu ?? 0) < (s.minAcu ?? 0)) out.push({ severity: 'error', title: `${name}: ACU máximas menores que las mínimas`, detail: 'Ajusta el rango de capacidad.', props: { maxAcu: s.minAcu ?? 2 } });
  return out;
}
