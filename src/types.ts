import type { Edge, Node } from '@xyflow/react';

/** Rol funcional de una pieza: es lo que usan las reglas de conexión. */
export type Role =
  | 'actor'
  | 'external'
  | 'dns'
  | 'cdn'
  | 'waf'
  | 'lb'
  | 'api'
  | 'compute'
  | 'registry'
  | 'datastore'
  | 'cache'
  | 'storage'
  | 'search'
  | 'queue'
  | 'topic'
  | 'eventbus'
  | 'stream'
  | 'workflow'
  | 'identity'
  | 'secrets'
  | 'kms'
  | 'cert'
  | 'observability'
  | 'netgw'
  | 'analytics'
  | 'ai'
  | 'devops';

/** Capa lógica de la arquitectura (para la vista por capas y el documento). */
export type Layer =
  | 'actores'
  | 'borde'
  | 'aplicacion'
  | 'integracion'
  | 'datos'
  | 'seguridad'
  | 'observabilidad'
  | 'red';

/** Dónde puede ubicarse una pieza. 'outside' = fuera de la VPC (global o regional). */
export type Placement = 'outside' | 'region' | 'subnet-public' | 'subnet-private' | 'subnet-data';

export type ZoneKind = 'region' | 'vpc' | 'subnet-public' | 'subnet-private' | 'subnet-data' | 'boundary';

export type PropDef =
  | { key: string; label: string; type: 'text'; default: string; help?: string }
  | { key: string; label: string; type: 'number'; default: number; min?: number; max?: number; help?: string }
  | { key: string; label: string; type: 'bool'; default: boolean; help?: string }
  | { key: string; label: string; type: 'select'; default: string; options: string[]; help?: string };

export type PropValue = string | number | boolean;

export interface ServiceDef {
  id: string;
  provider: 'aws' | 'generic';
  name: string;
  short: string;
  category: CategoryId;
  role: Role;
  layer: Layer;
  zones: Placement[];
  description: string;
  /** Protocolo sugerido cuando alguien se conecta HACIA esta pieza. */
  inboundProtocol?: string;
  props?: PropDef[];
  /** Si es true la pieza debe vivir en una subnet (VPC). */
  vpcBound?: boolean;
  /** Puede iniciar eventos hacia cómputo/colas (S3 events, DynamoDB Streams...). */
  emitsEvents?: boolean;
}

export type CategoryId =
  | 'generic'
  | 'networking'
  | 'compute'
  | 'containers'
  | 'storage'
  | 'database'
  | 'integration'
  | 'security'
  | 'observability'
  | 'analytics'
  | 'ai'
  | 'devops';

export interface ServiceData extends Record<string, unknown> {
  serviceId: string;
  label: string;
  props: Record<string, PropValue>;
  notes?: string;
  /** Estado de validación, calculado (no se persiste). */
  issue?: 'error' | 'warn' | 'info';
  dimmed?: boolean;
}

export interface ZoneData extends Record<string, unknown> {
  zoneKind: ZoneKind;
  label: string;
  props: Record<string, PropValue>;
  issue?: 'error' | 'warn' | 'info';
  dimmed?: boolean;
}

export interface ConnData extends Record<string, unknown> {
  protocol: string;
  description?: string;
  async?: boolean;
  level?: 'ok' | 'warn';
  ruleMsg?: string;
}

export type ServiceNode = Node<ServiceData, 'service'>;
export type ZoneNode = Node<ZoneData, 'zone'>;
export type AppNode = ServiceNode | ZoneNode;
export type AppEdge = Edge<ConnData>;

export interface Decision {
  id: string;
  title: string;
  status: 'propuesta' | 'aceptada' | 'reemplazada' | 'rechazada';
  context: string;
  decision: string;
  consequences: string;
}

export interface ProjectMeta {
  name: string;
  description: string;
  author: string;
  provider: 'aws';
  region: string;
  environment: string;
  createdAt: string;
  updatedAt: string;
}

export type ThreatStatusOverride = 'aceptada' | 'no-aplica' | 'mitigada';

/** Estado que el arquitecto registra para una amenaza (se guarda en el proyecto). */
export interface ThreatState {
  status?: ThreatStatusOverride;
  note?: string;
  owner?: string;
  /** Controles manuales marcados como implementados. */
  controls?: Record<string, boolean>;
}

export interface Project {
  format: 'archiplan';
  version: 1;
  meta: ProjectMeta;
  nodes: AppNode[];
  edges: AppEdge[];
  decisions: Decision[];
  threats?: Record<string, ThreatState>;
}

export type Severity = 'error' | 'warn' | 'info';

export interface Issue {
  id: string;
  severity: Severity;
  title: string;
  detail: string;
  nodeIds: string[];
  edgeIds?: string[];
  fix?: Fix;
}

/** Arreglo automático propuesto por una regla: agregar piezas y conectarlas. */
export interface Fix {
  label: string;
  add?: { serviceId: string; label?: string; near?: string; parent?: string | null; props?: Record<string, PropValue> }[];
  /** Conexiones a crear. 'new:N' referencia la N-ésima pieza agregada. */
  connect?: { source: string; target: string; protocol?: string }[];
  setProps?: { nodeId: string; props: Record<string, PropValue> }[];
}
