/**
 * Estimación de costo mensual por pieza.
 *
 * IMPORTANTE: es una estimación de orden de magnitud con precios de lista on‑demand de
 * us‑east‑1 (sin impuestos, free tier, descuentos ni Savings Plans). Sirve para comparar
 * variantes de un mismo diseño, no para presupuestar. Las piezas de Azure se estiman con su
 * equivalente de AWS. Los precios están juntos en PRICES para poder ajustarlos.
 */
import { getService, lid } from '../catalog/catalog';
import { scalingOf } from '../scaling/model';
import type { ServiceNode } from '../types';

const H = 730; // horas por mes
const MREQ = 2.628e6; // segundos por mes (30,4 días) → req/s × MREQ = peticiones al mes

export const PRICES = {
  ec2Hour: { nano: 0.0052, micro: 0.0104, small: 0.0208, medium: 0.0416, large: 0.0832, xlarge: 0.1664, '2xlarge': 0.3328, '4xlarge': 0.6656 } as Record<string, number>,
  ebsGbMonth: 0.08,
  albMonth: 16.43,
  lcuMonth: 5.84,
  natMonth: 32.85,
  natGb: 0.045,
  cfPerMillion: 1.0,
  cfGb: 0.085,
  apigwHttpPerMillion: 1.0,
  apigwRestPerMillion: 3.5,
  lambdaPerMillion: 0.2,
  lambdaGbSecond: 0.0000166667,
  fargateVcpuHour: 0.04048,
  fargateGbHour: 0.004445,
  eksClusterMonth: 73,
  appRunnerInstanceMonth: 57,
  rdsHour: { micro: 0.016, small: 0.032, medium: 0.065, large: 0.129, xlarge: 0.258, '2xlarge': 0.516 } as Record<string, number>,
  rdsGbMonth: 0.115,
  auroraAcuHour: 0.12,
  auroraInstanceHour: 0.26,
  auroraGbMonth: 0.1,
  ddbReadPerMillion: 0.125,
  ddbWritePerMillion: 0.625,
  ddbRcuHour: 0.00013,
  ddbWcuHour: 0.00065,
  cacheHour: { micro: 0.016, small: 0.032, medium: 0.065, large: 0.149, xlarge: 0.298 } as Record<string, number>,
  s3GbMonth: 0.023,
  s3GetPerMillion: 0.4,
  s3PutPerMillion: 5,
  sqsPerMillion: 0.4,
  snsPerMillion: 0.5,
  eventsPerMillion: 1.0,
  sfnStandardPerMillionTransitions: 25,
  sfnExpressPerMillion: 1.0,
  kinesisStreamMonth: 29.2,
  wafAclMonth: 5,
  wafRuleMonth: 1,
  wafPerMillion: 0.6,
  wafBotControlMonth: 10,
  shieldAdvancedMonth: 3000,
  secretMonth: 0.4,
  kmsKeyMonth: 1,
  logsGb: 0.5,
  r53ZoneMonth: 0.5,
  r53PerMillion: 0.4,
  vpceInterfaceMonth: 14.6,
  vpnMonth: 36.5,
  guarddutyMonth: 30,
  openSearchHour: 0.073,
  docdbHour: 0.277,
  redshiftMonth: 793,
  mskBrokerHour: 0.21,
  bedrockPerRequest: 0.0105,
  sagemakerMonth: 84,
};

export interface CostItem {
  nodeId: string;
  label: string;
  monthly: number;
  basis: string;
}

const sizeOf = (t: string) => t.toLowerCase().split('.').pop() ?? 'medium';
const fmt = (n: number) => (n >= 100 ? Math.round(n).toLocaleString('es-CO') : n.toFixed(2));

/** Costo mensual estimado de una pieza, dado el tráfico que recibe (req/s promedio). */
export function estimateCost(n: ServiceNode, rps: number, opts: { respKb?: number } = {}): CostItem {
  const p = n.data.props;
  const P = PRICES;
  const req = Math.max(0, rps) * MREQ; // peticiones al mes
  const M = req / 1e6;
  const sc = scalingOf(n);
  const item = (monthly: number, basis: string): CostItem => ({ nodeId: n.id, label: n.data.label, monthly: Math.max(0, monthly), basis });
  const azure = n.data.serviceId.startsWith('az-') ? ' (estimado con el equivalente de AWS)' : '';
  switch (lid(n)) {
    case 'ec2':
    case 'beanstalk': {
      const type = String(p.instanceType ?? 't3.medium');
      const az = type.match(/^standard_[a-z]+(\d+)/i);
      const hour = az ? Number(az[1]) * 0.048 : (P.ec2Hour[sizeOf(type)] ?? 0.0416) * (/^(m\d)/i.test(type) ? 2.3 : /^(c\d)/i.test(type) ? 2.05 : /^(r\d)/i.test(type) ? 3 : /^t4g/i.test(type) ? 0.8 : 1);
      const k = sc?.desired ?? 2;
      return item(k * (hour * H + 20 * P.ebsGbMonth), `${k} × ${type} (${hour.toFixed(4)} US$/h) + disco${azure}`);
    }
    case 'lightsail':
      return item(String(p.bundle ?? '').startsWith('nano') ? 5 : String(p.bundle ?? '').startsWith('medium') ? 24 : String(p.bundle ?? '').startsWith('large') ? 44 : 12, 'Plan de precio fijo');
    case 'lambda': {
      const mem = Number(p.memory) || 512;
      const dur = Number(p['sim.durationMs']) || 120;
      const gbs = req * (dur / 1000) * (mem / 1024);
      return item(M * P.lambdaPerMillion + gbs * P.lambdaGbSecond, `${fmt(M)} M invocaciones × ${dur} ms × ${mem} MB${azure}`);
    }
    case 'ecs': {
      const vcpu = (Number(p.cpu) || 512) / 1024;
      const gb = (Number(p.memory) || 1024) / 1024;
      const k = Math.max(1, sc?.desired ?? 2);
      return item(k * H * (vcpu * P.fargateVcpuHour + gb * P.fargateGbHour), `${k} tareas Fargate de ${vcpu} vCPU / ${gb} GB${azure}`);
    }
    case 'eks': {
      const k = sc?.desired ?? 3;
      return item(P.eksClusterMonth + k * P.ec2Hour.large * 2.3 * H, `Plano de control + ${k} nodos m5.large${azure}`);
    }
    case 'apprunner':
      return item((sc?.desired ?? 1) * P.appRunnerInstanceMonth, `${sc?.desired ?? 1} instancia(s) activas de 1 vCPU / 2 GB${azure}`);
    case 'alb':
    case 'nlb': {
      const lcu = Math.max(1, rps / 100);
      return item(P.albMonth + lcu * P.lcuMonth, `Balanceador + ~${lcu.toFixed(1)} LCU${azure}`);
    }
    case 'natgw': {
      const gb = (req * 2) / 1e6;
      return item(P.natMonth + gb * P.natGb, `Hora del NAT + ~${fmt(gb)} GB procesados`);
    }
    case 'cloudfront': {
      const kb = opts.respKb ?? 20;
      const gb = (req * kb) / 1e6;
      return item(M * P.cfPerMillion + gb * P.cfGb, `${fmt(M)} M peticiones + ~${fmt(gb)} GB (${kb} KB por respuesta)${azure}`);
    }
    case 'apigw': {
      const rest = String(p.type ?? '') === 'REST API';
      return item(M * (rest ? P.apigwRestPerMillion : P.apigwHttpPerMillion), `${fmt(M)} M peticiones (${rest ? 'REST' : 'HTTP API'})${azure}`);
    }
    case 'rds': {
      const cls = String(p.instanceClass ?? 'db.t4g.medium');
      const hour = P.rdsHour[sizeOf(cls)] ?? 0.065;
      const multi = p.multiAZ ? 2 : 1;
      const gb = Number(p.storage) || 50;
      return item(multi * (hour * H + gb * P.rdsGbMonth), `${cls}${multi > 1 ? ' Multi‑AZ (×2)' : ''} + ${gb} GB${azure}`);
    }
    case 'aurora': {
      const inst = 1 + (sc?.replicas ?? 1);
      if (sc?.serverless) return item(inst * (sc.minAcu ?? 2) * P.auroraAcuHour * H + 50 * P.auroraGbMonth, `${inst} instancia(s) × ${sc.minAcu} ACU mínimas (sube con la carga) + 50 GB${azure}`);
      return item(inst * P.auroraInstanceHour * H + 50 * P.auroraGbMonth, `${inst} × db.r6g.large + 50 GB${azure}`);
    }
    case 'dynamodb': {
      if (sc?.billing === 'PROVISIONED') {
        const rcu = sc.rcu ?? 1000;
        return item(H * (rcu * P.ddbRcuHour + (rcu / 4) * P.ddbWcuHour) + 10 * 0.25, `${rcu} RCU + ${Math.round(rcu / 4)} WCU provisionadas${azure}`);
      }
      return item(M * (0.8 * P.ddbReadPerMillion + 0.2 * P.ddbWritePerMillion) + 10 * 0.25, `On‑demand: ${fmt(M)} M operaciones (80 % lecturas)${azure}`);
    }
    case 'elasticache':
    case 'memorydb': {
      const nodes = (1 + (Number(p.replicas) || 0)) * (Number(p.shards) || 1);
      const hour = P.cacheHour[sizeOf(String(p.nodeType ?? 'cache.t4g.small'))] ?? 0.032;
      return item(nodes * hour * H * (lid(n) === 'memorydb' ? 1.4 : 1), `${nodes} nodo(s) ${String(p.nodeType ?? 'cache.t4g.small')}${azure}`);
    }
    case 's3':
      return item(100 * P.s3GbMonth + M * (0.9 * P.s3GetPerMillion + 0.1 * P.s3PutPerMillion), `100 GB + ${fmt(M)} M peticiones${azure}`);
    case 'sqs':
      return item(M * 3 * P.sqsPerMillion, `${fmt(M)} M mensajes × 3 llamadas${azure}`);
    case 'sns':
      return item(M * P.snsPerMillion, `${fmt(M)} M publicaciones${azure}`);
    case 'eventbridge':
    case 'scheduler':
      return item(M * P.eventsPerMillion, `${fmt(M)} M eventos${azure}`);
    case 'stepfunctions':
      return item(String(p.type) === 'EXPRESS' ? M * P.sfnExpressPerMillion : M * 5 * P.sfnStandardPerMillionTransitions, `${fmt(M)} M ejecuciones${azure}`);
    case 'kinesis':
    case 'firehose':
      return item(P.kinesisStreamMonth + (req * 1) / 1e6 * 0.08, 'Stream on‑demand + datos');
    case 'waf': {
      const rules = 2 + (p.sqliRules !== false ? 1 : 0) + (p.managedRules !== false ? 1 : 0);
      return item(P.wafAclMonth + rules * P.wafRuleMonth + (p.botControl ? P.wafBotControlMonth + M * 1 : 0) + M * P.wafPerMillion, `Web ACL + ${rules} reglas + ${fmt(M)} M peticiones${p.botControl ? ' + Bot Control' : ''}${azure}`);
    }
    case 'shield':
      return item(P.shieldAdvancedMonth, 'Shield Advanced (cuota fija por organización)');
    case 'secrets':
      return item(3 * P.secretMonth + M * 0.5, '3 secretos + llamadas');
    case 'kms':
      return item(P.kmsKeyMonth, '1 llave');
    case 'cloudwatch': {
      const gb = (req * 1) / 1e6;
      return item(gb * P.logsGb + 10, `~${fmt(gb)} GB de logs (1 KB por petición) + métricas`);
    }
    case 'xray':
      return item(M * 0.05 * 5, 'Trazas al 5 %');
    case 'route53':
      return item(P.r53ZoneMonth + (M / 10) * P.r53PerMillion, 'Zona + consultas');
    case 'vpce':
      return item(['s3', 'dynamodb'].includes(String(p.service)) ? 0 : P.vpceInterfaceMonth, ['s3', 'dynamodb'].includes(String(p.service)) ? 'Endpoint de gateway (gratis)' : 'Endpoint de interfaz en 2 AZ');
    case 'vpn':
      return item(P.vpnMonth, 'Conexión VPN');
    case 'guardduty':
      return item(P.guarddutyMonth, 'Supuesto para una cuenta pequeña');
    case 'opensearch':
      return item((Number(p.instances) || 2) * P.openSearchHour * H, `${Number(p.instances) || 2} nodos t3.medium`);
    case 'documentdb':
      return item((Number(p.instances) || 2) * P.docdbHour * H, `${Number(p.instances) || 2} instancias r6g.large`);
    case 'redshift':
      return item(P.redshiftMonth, '1 nodo ra3.xlplus');
    case 'msk':
      return item((Number(p.brokers) || 3) * P.mskBrokerHour * H, `${Number(p.brokers) || 3} brokers m5.large`);
    case 'bedrock':
      return item(req * P.bedrockPerRequest, `${fmt(M)} M llamadas × ~1.500 tokens`);
    case 'sagemaker':
      return item(P.sagemakerMonth, '1 endpoint ml.m5.large');
    case 'cognito':
      return item(0, 'Depende de usuarios activos (las primeras decenas de miles son baratas o gratis)');
    default:
      return item(0, ['actor', 'external', 'dns', 'cert', 'netgw'].includes(getService(n.data.serviceId).role) ? 'Sin costo propio o fuera de AWS' : 'No estimado');
  }
}
