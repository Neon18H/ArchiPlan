import type { CategoryId, Layer, PropDef, ServiceDef, ZoneKind } from '../types';

export const CATEGORIES: Record<CategoryId, { label: string; color: string }> = {
  generic: { label: 'Actores y externos', color: '#5c677d' },
  networking: { label: 'Red y entrega de contenido', color: '#8C4FFF' },
  compute: { label: 'Cómputo', color: '#ED7100' },
  containers: { label: 'Contenedores', color: '#D86613' },
  storage: { label: 'Almacenamiento', color: '#7AA116' },
  database: { label: 'Bases de datos', color: '#C925D1' },
  integration: { label: 'Integración de aplicaciones', color: '#E7157B' },
  security: { label: 'Seguridad e identidad', color: '#DD344C' },
  observability: { label: 'Observabilidad y gestión', color: '#B0084D' },
  analytics: { label: 'Analítica', color: '#6B40D8' },
  ai: { label: 'IA / Machine Learning', color: '#01A88D' },
  devops: { label: 'DevOps', color: '#3F8624' },
};

export const LAYERS: Record<Layer, { label: string; order: number }> = {
  actores: { label: 'Actores y sistemas externos', order: 0 },
  borde: { label: 'Borde / Entrada', order: 1 },
  aplicacion: { label: 'Aplicación', order: 2 },
  integracion: { label: 'Integración', order: 3 },
  datos: { label: 'Datos', order: 4 },
  seguridad: { label: 'Seguridad', order: 5 },
  observabilidad: { label: 'Observabilidad', order: 6 },
  red: { label: 'Red', order: 7 },
};

export const ZONES: Record<ZoneKind, { label: string; color: string; bg: string; help: string; props: PropDef[] }> = {
  region: {
    label: 'Región AWS',
    color: '#147EBA',
    bg: 'rgba(20,126,186,0.04)',
    help: 'Contenedor de los recursos regionales (VPC, Lambda, S3, SQS...).',
    props: [{ key: 'region', label: 'Región', type: 'text', default: 'us-east-1' }],
  },
  vpc: {
    label: 'VPC',
    color: '#8C4FFF',
    bg: 'rgba(140,79,255,0.04)',
    help: 'Red privada virtual. Debe ir dentro de una región.',
    props: [
      { key: 'cidr', label: 'CIDR', type: 'text', default: '10.0.0.0/16' },
      { key: 'azs', label: 'Zonas de disponibilidad', type: 'number', default: 2, min: 1, max: 6 },
    ],
  },
  'subnet-public': {
    label: 'Subnet pública',
    color: '#7AA116',
    bg: 'rgba(122,161,22,0.06)',
    help: 'Tiene ruta a Internet Gateway. Solo para balanceadores, NAT y bastiones.',
    props: [{ key: 'cidr', label: 'CIDR', type: 'text', default: '10.0.0.0/24' }],
  },
  'subnet-private': {
    label: 'Subnet privada',
    color: '#147EBA',
    bg: 'rgba(20,126,186,0.06)',
    help: 'Sin entrada desde Internet. Aquí vive el cómputo de la aplicación.',
    props: [{ key: 'cidr', label: 'CIDR', type: 'text', default: '10.0.10.0/24' }],
  },
  'subnet-data': {
    label: 'Subnet de datos',
    color: '#C925D1',
    bg: 'rgba(201,37,209,0.05)',
    help: 'Aislada: solo accesible desde la capa de aplicación. Aquí van las bases de datos.',
    props: [{ key: 'cidr', label: 'CIDR', type: 'text', default: '10.0.20.0/24' }],
  },
  boundary: {
    label: 'Límite / Grupo',
    color: '#5c677d',
    bg: 'rgba(92,103,125,0.04)',
    help: 'Agrupación libre: on‑premise, otro equipo, contexto de negocio, etc.',
    props: [],
  },
};

/** Qué zona puede contener a cuál. */
export const ZONE_PARENT: Record<ZoneKind, (ZoneKind | null)[]> = {
  region: [null, 'boundary'],
  vpc: ['region'],
  'subnet-public': ['vpc'],
  'subnet-private': ['vpc'],
  'subnet-data': ['vpc'],
  boundary: [null, 'boundary', 'region'],
};

const OUT_REG = ['outside', 'region'] as const;
export const DATA_CLASSES = ['Público', 'Interno', 'Confidencial', 'Restringido'] as const;
const DATA_CLASS: PropDef = { key: 'dataClass', label: 'Clasificación de los datos', type: 'select', default: 'Confidencial', options: [...DATA_CLASSES], help: 'Define el impacto en el modelo de amenazas. Restringido: datos personales, financieros o de salud.' };
const VPC_APP = ['subnet-private', 'subnet-public'] as const;

const S = (d: Omit<ServiceDef, 'provider'> & { provider?: ServiceDef['provider'] }): ServiceDef => ({
  provider: 'aws',
  ...d,
  zones: [...d.zones],
});

export const SERVICES: ServiceDef[] = [
  // ───────── Genéricos
  S({ id: 'user', provider: 'generic', name: 'Usuario', short: 'USR', category: 'generic', role: 'actor', layer: 'actores', zones: ['outside'], description: 'Persona que usa el sistema (web o móvil).', props: [{ key: 'channel', label: 'Canal', type: 'select', default: 'Web', options: ['Web', 'Móvil', 'Escritorio', 'API'] }] }),
  S({ id: 'admin', provider: 'generic', name: 'Administrador', short: 'ADM', category: 'generic', role: 'actor', layer: 'actores', zones: ['outside'], description: 'Operador interno o backoffice.' }),
  S({ id: 'external', provider: 'generic', name: 'Sistema externo', short: 'EXT', category: 'generic', role: 'external', layer: 'actores', zones: ['outside'], description: 'API de terceros, pasarela de pagos, ERP, etc.', inboundProtocol: 'HTTPS', props: [{ key: 'kind', label: 'Tipo', type: 'select', default: 'API REST', options: ['API REST', 'SOAP', 'SFTP', 'Webhook', 'Base de datos', 'Otro'] }] }),
  S({ id: 'onprem', provider: 'generic', name: 'Centro de datos on‑premise', short: 'DC', category: 'generic', role: 'external', layer: 'actores', zones: ['outside'], description: 'Infraestructura propia conectada por VPN o Direct Connect.', inboundProtocol: 'VPN/IPsec' }),

  // ───────── Red
  S({ id: 'route53', name: 'Amazon Route 53', short: 'R53', category: 'networking', role: 'dns', layer: 'borde', zones: ['outside'], description: 'DNS administrado y enrutamiento por salud/latencia.', inboundProtocol: 'DNS', props: [{ key: 'domain', label: 'Dominio', type: 'text', default: 'ejemplo.com' }] }),
  S({ id: 'cloudfront', name: 'Amazon CloudFront', short: 'CF', category: 'networking', role: 'cdn', layer: 'borde', zones: ['outside'], description: 'CDN global con caché en el borde y TLS.', inboundProtocol: 'HTTPS', props: [{ key: 'priceClass', label: 'Clase de precio', type: 'select', default: 'PriceClass_100', options: ['PriceClass_100', 'PriceClass_200', 'PriceClass_All'] }] }),
  S({ id: 'alb', name: 'Application Load Balancer', short: 'ALB', category: 'networking', role: 'lb', layer: 'borde', zones: [...VPC_APP], vpcBound: true, description: 'Balanceador L7 (HTTP/HTTPS) con reglas por ruta/host.', inboundProtocol: 'HTTPS', props: [{ key: 'scheme', label: 'Esquema', type: 'select', default: 'internet-facing', options: ['internet-facing', 'internal'] }] }),
  S({ id: 'nlb', name: 'Network Load Balancer', short: 'NLB', category: 'networking', role: 'lb', layer: 'borde', zones: [...VPC_APP], vpcBound: true, description: 'Balanceador L4 (TCP/UDP) de ultra baja latencia.', inboundProtocol: 'TCP', props: [{ key: 'scheme', label: 'Esquema', type: 'select', default: 'internal', options: ['internet-facing', 'internal'] }] }),
  S({ id: 'apigw', name: 'Amazon API Gateway', short: 'APIGW', category: 'networking', role: 'api', layer: 'borde', zones: [...OUT_REG], description: 'API REST/HTTP/WebSocket administrada, con throttling y autorizadores.', inboundProtocol: 'HTTPS', props: [{ key: 'type', label: 'Tipo', type: 'select', default: 'HTTP API', options: ['HTTP API', 'REST API', 'WebSocket'] }] }),
  S({ id: 'natgw', name: 'NAT Gateway', short: 'NAT', category: 'networking', role: 'netgw', layer: 'red', zones: ['subnet-public'], vpcBound: true, description: 'Salida a Internet para subnets privadas.' }),
  S({ id: 'igw', name: 'Internet Gateway', short: 'IGW', category: 'networking', role: 'netgw', layer: 'red', zones: ['region', 'outside'], description: 'Puerta de la VPC hacia Internet.' }),
  S({ id: 'vpce', name: 'VPC Endpoint', short: 'VPCE', category: 'networking', role: 'netgw', layer: 'red', zones: ['subnet-private', 'subnet-data'], vpcBound: true, description: 'Acceso privado a servicios AWS (S3, DynamoDB, SQS...) sin pasar por Internet.', props: [{ key: 'service', label: 'Servicio', type: 'select', default: 's3', options: ['s3', 'dynamodb', 'sqs', 'secretsmanager', 'ecr.api', 'logs'] }] }),
  S({ id: 'vpn', name: 'Site‑to‑Site VPN', short: 'VPN', category: 'networking', role: 'netgw', layer: 'red', zones: ['region', 'outside'], description: 'Túnel IPsec hacia on‑premise.' }),

  // ───────── Cómputo
  S({ id: 'ec2', name: 'Amazon EC2', short: 'EC2', category: 'compute', role: 'compute', layer: 'aplicacion', zones: [...VPC_APP], vpcBound: true, description: 'Máquinas virtuales.', inboundProtocol: 'HTTP 8080', props: [
    { key: 'instanceType', label: 'Tipo de instancia', type: 'text', default: 't3.medium' },
    { key: 'count', label: 'Instancias', type: 'number', default: 2, min: 1, max: 100 },
    { key: 'autoscaling', label: 'Auto Scaling Group', type: 'bool', default: true },
  ] }),
  S({ id: 'lambda', name: 'AWS Lambda', short: 'λ', category: 'compute', role: 'compute', layer: 'aplicacion', zones: ['outside', 'region', 'subnet-private'], description: 'Funciones serverless por eventos.', inboundProtocol: 'Invoke', props: [
    { key: 'runtime', label: 'Runtime', type: 'select', default: 'nodejs20.x', options: ['nodejs20.x', 'python3.12', 'java21', 'go (provided.al2023)', 'dotnet8'] },
    { key: 'memory', label: 'Memoria (MB)', type: 'number', default: 512, min: 128, max: 10240 },
    { key: 'timeout', label: 'Timeout (s)', type: 'number', default: 30, min: 1, max: 900 },
  ] }),
  S({ id: 'ecs', name: 'Amazon ECS (Fargate)', short: 'ECS', category: 'containers', role: 'compute', layer: 'aplicacion', zones: [...VPC_APP], vpcBound: true, description: 'Servicio de contenedores sin administrar servidores.', inboundProtocol: 'HTTP 8080', props: [
    { key: 'cpu', label: 'CPU (unidades)', type: 'number', default: 512 },
    { key: 'memory', label: 'Memoria (MB)', type: 'number', default: 1024 },
    { key: 'desired', label: 'Tareas deseadas', type: 'number', default: 2, min: 1 },
    { key: 'image', label: 'Imagen', type: 'text', default: 'app:latest' },
  ] }),
  S({ id: 'eks', name: 'Amazon EKS', short: 'EKS', category: 'containers', role: 'compute', layer: 'aplicacion', zones: [...VPC_APP], vpcBound: true, description: 'Kubernetes administrado.', inboundProtocol: 'HTTP', props: [
    { key: 'version', label: 'Versión K8s', type: 'text', default: '1.31' },
    { key: 'nodes', label: 'Nodos', type: 'number', default: 3, min: 1 },
  ] }),
  S({ id: 'ecr', name: 'Amazon ECR', short: 'ECR', category: 'containers', role: 'registry', layer: 'aplicacion', zones: [...OUT_REG], description: 'Registro privado de imágenes de contenedor.', inboundProtocol: 'HTTPS (pull)' }),
  S({ id: 'apprunner', name: 'AWS App Runner', short: 'AR', category: 'containers', role: 'compute', layer: 'aplicacion', zones: [...OUT_REG], description: 'Despliega contenedores web sin gestionar balanceadores ni clústeres.', inboundProtocol: 'HTTPS' }),

  // ───────── Almacenamiento
  S({ id: 's3', name: 'Amazon S3', short: 'S3', category: 'storage', role: 'storage', layer: 'datos', zones: [...OUT_REG], emitsEvents: true, description: 'Almacenamiento de objetos (archivos, estáticos, data lake).', inboundProtocol: 'HTTPS (S3 API)', props: [DATA_CLASS, 
    { key: 'public', label: 'Acceso público', type: 'bool', default: false },
    { key: 'versioning', label: 'Versionado', type: 'bool', default: true },
    { key: 'encrypted', label: 'Cifrado (SSE)', type: 'bool', default: true },
  ] }),
  S({ id: 'efs', name: 'Amazon EFS', short: 'EFS', category: 'storage', role: 'storage', layer: 'datos', zones: ['subnet-private', 'subnet-data'], vpcBound: true, description: 'Sistema de archivos NFS compartido.', inboundProtocol: 'NFS 2049', props: [DATA_CLASS, { key: 'encrypted', label: 'Cifrado', type: 'bool', default: true }] }),

  // ───────── Bases de datos
  S({ id: 'rds', name: 'Amazon RDS', short: 'RDS', category: 'database', role: 'datastore', layer: 'datos', zones: ['subnet-data', 'subnet-private'], vpcBound: true, description: 'Base de datos relacional administrada.', inboundProtocol: 'SQL', props: [DATA_CLASS, 
    { key: 'engine', label: 'Motor', type: 'select', default: 'postgres', options: ['postgres', 'mysql', 'mariadb', 'sqlserver-ex', 'oracle-se2'] },
    { key: 'instanceClass', label: 'Clase', type: 'text', default: 'db.t4g.medium' },
    { key: 'multiAZ', label: 'Multi‑AZ', type: 'bool', default: true },
    { key: 'encrypted', label: 'Cifrado en reposo', type: 'bool', default: true },
    { key: 'storage', label: 'Almacenamiento (GB)', type: 'number', default: 50 },
  ] }),
  S({ id: 'aurora', name: 'Amazon Aurora', short: 'AUR', category: 'database', role: 'datastore', layer: 'datos', zones: ['subnet-data', 'subnet-private'], vpcBound: true, description: 'Relacional compatible con MySQL/PostgreSQL, alta disponibilidad nativa.', inboundProtocol: 'SQL', props: [DATA_CLASS, 
    { key: 'engine', label: 'Motor', type: 'select', default: 'aurora-postgresql', options: ['aurora-postgresql', 'aurora-mysql'] },
    { key: 'serverless', label: 'Serverless v2', type: 'bool', default: true },
    { key: 'replicas', label: 'Réplicas de lectura', type: 'number', default: 1, min: 0, max: 15 },
    { key: 'encrypted', label: 'Cifrado en reposo', type: 'bool', default: true },
  ] }),
  S({ id: 'dynamodb', name: 'Amazon DynamoDB', short: 'DDB', category: 'database', role: 'datastore', layer: 'datos', zones: [...OUT_REG], emitsEvents: true, description: 'NoSQL clave‑valor serverless de baja latencia.', inboundProtocol: 'HTTPS (DynamoDB API)', props: [DATA_CLASS, 
    { key: 'billing', label: 'Facturación', type: 'select', default: 'PAY_PER_REQUEST', options: ['PAY_PER_REQUEST', 'PROVISIONED'] },
    { key: 'pk', label: 'Partition key', type: 'text', default: 'pk' },
    { key: 'streams', label: 'DynamoDB Streams', type: 'bool', default: false },
    { key: 'pitr', label: 'Point‑in‑time recovery', type: 'bool', default: true },
  ] }),
  S({ id: 'elasticache', name: 'Amazon ElastiCache', short: 'EC', category: 'database', role: 'cache', layer: 'datos', zones: ['subnet-data', 'subnet-private'], vpcBound: true, description: 'Caché en memoria (Redis/Valkey/Memcached).', inboundProtocol: 'Redis 6379', props: [DATA_CLASS, 
    { key: 'engine', label: 'Motor', type: 'select', default: 'valkey', options: ['valkey', 'redis', 'memcached'] },
    { key: 'nodeType', label: 'Tipo de nodo', type: 'text', default: 'cache.t4g.small' },
    { key: 'replicas', label: 'Réplicas', type: 'number', default: 1, min: 0 },
  ] }),
  S({ id: 'documentdb', name: 'Amazon DocumentDB', short: 'DOC', category: 'database', role: 'datastore', layer: 'datos', zones: ['subnet-data', 'subnet-private'], vpcBound: true, description: 'Base documental compatible con MongoDB.', inboundProtocol: 'MongoDB 27017', props: [DATA_CLASS, { key: 'instances', label: 'Instancias', type: 'number', default: 2 }, { key: 'encrypted', label: 'Cifrado en reposo', type: 'bool', default: true }] }),
  S({ id: 'opensearch', name: 'Amazon OpenSearch', short: 'OS', category: 'database', role: 'search', layer: 'datos', zones: ['subnet-data', 'subnet-private'], vpcBound: true, description: 'Búsqueda de texto completo y analítica de logs.', inboundProtocol: 'HTTPS 443', props: [DATA_CLASS, { key: 'instances', label: 'Nodos de datos', type: 'number', default: 2 }, { key: 'encrypted', label: 'Cifrado en reposo', type: 'bool', default: true }] }),

  // ───────── Integración
  S({ id: 'sqs', name: 'Amazon SQS', short: 'SQS', category: 'integration', role: 'queue', layer: 'integracion', zones: [...OUT_REG], description: 'Cola de mensajes para desacoplar productores y consumidores.', inboundProtocol: 'async (SendMessage)', props: [
    { key: 'fifo', label: 'FIFO', type: 'bool', default: false },
    { key: 'dlq', label: 'Dead‑letter queue', type: 'bool', default: false },
    { key: 'visibility', label: 'Visibility timeout (s)', type: 'number', default: 60 },
  ] }),
  S({ id: 'sns', name: 'Amazon SNS', short: 'SNS', category: 'integration', role: 'topic', layer: 'integracion', zones: [...OUT_REG], description: 'Pub/sub y notificaciones (fan‑out, correo, SMS).', inboundProtocol: 'async (Publish)' }),
  S({ id: 'eventbridge', name: 'Amazon EventBridge', short: 'EB', category: 'integration', role: 'eventbus', layer: 'integracion', zones: [...OUT_REG], description: 'Bus de eventos con reglas y enrutamiento.', inboundProtocol: 'async (PutEvents)', props: [{ key: 'bus', label: 'Nombre del bus', type: 'text', default: 'app-events' }] }),
  S({ id: 'stepfunctions', name: 'AWS Step Functions', short: 'SFN', category: 'integration', role: 'workflow', layer: 'integracion', zones: [...OUT_REG], description: 'Orquestación de flujos y sagas.', inboundProtocol: 'StartExecution', props: [{ key: 'type', label: 'Tipo', type: 'select', default: 'STANDARD', options: ['STANDARD', 'EXPRESS'] }] }),
  S({ id: 'kinesis', name: 'Kinesis Data Streams', short: 'KDS', category: 'integration', role: 'stream', layer: 'integracion', zones: [...OUT_REG], description: 'Streaming de datos en tiempo real.', inboundProtocol: 'async (PutRecords)', props: [{ key: 'mode', label: 'Modo', type: 'select', default: 'ON_DEMAND', options: ['ON_DEMAND', 'PROVISIONED'] }] }),
  S({ id: 'firehose', name: 'Amazon Data Firehose', short: 'FH', category: 'integration', role: 'stream', layer: 'integracion', zones: [...OUT_REG], description: 'Entrega de streams hacia S3, Redshift u OpenSearch.', inboundProtocol: 'async' }),
  S({ id: 'msk', name: 'Amazon MSK (Kafka)', short: 'MSK', category: 'integration', role: 'stream', layer: 'integracion', zones: ['subnet-private', 'subnet-data'], vpcBound: true, description: 'Apache Kafka administrado.', inboundProtocol: 'Kafka 9098', props: [{ key: 'brokers', label: 'Brokers', type: 'number', default: 3 }] }),

  // ───────── Seguridad
  S({ id: 'waf', name: 'AWS WAF', short: 'WAF', category: 'security', role: 'waf', layer: 'seguridad', zones: ['outside', 'region'], description: 'Firewall de aplicación web (OWASP, rate limiting, bots).', props: [
    { key: 'managedRules', label: 'Core Rule Set (OWASP: XSS, LFI…)', type: 'bool', default: true },
    { key: 'sqliRules', label: 'Reglas de inyección SQL', type: 'bool', default: true },
    { key: 'botControl', label: 'Bot Control', type: 'bool', default: false, help: 'Grupo de pago: detecta bots y scrapers aunque vengan de muchas IPs.' },
    { key: 'rateLimit', label: 'Límite req/5min por IP', type: 'number', default: 2000 },
  ] }),
  S({ id: 'shield', name: 'AWS Shield Advanced', short: 'SHD', category: 'security', role: 'waf', layer: 'seguridad', zones: ['outside'], description: 'Protección DDoS avanzada.' }),
  S({ id: 'cognito', name: 'Amazon Cognito', short: 'COG', category: 'security', role: 'identity', layer: 'seguridad', zones: [...OUT_REG], emitsEvents: true, description: 'Registro, login y emisión de tokens (OIDC/OAuth2).', inboundProtocol: 'OIDC/HTTPS', props: [{ key: 'mfa', label: 'MFA', type: 'select', default: 'OPTIONAL', options: ['OFF', 'OPTIONAL', 'ON'] }] }),
  S({ id: 'secrets', name: 'AWS Secrets Manager', short: 'SM', category: 'security', role: 'secrets', layer: 'seguridad', zones: [...OUT_REG], description: 'Credenciales y secretos con rotación.', inboundProtocol: 'HTTPS (GetSecretValue)', props: [{ key: 'rotation', label: 'Rotación automática', type: 'bool', default: true }] }),
  S({ id: 'kms', name: 'AWS KMS', short: 'KMS', category: 'security', role: 'kms', layer: 'seguridad', zones: [...OUT_REG], description: 'Llaves de cifrado administradas.', inboundProtocol: 'HTTPS (KMS API)' }),
  S({ id: 'acm', name: 'AWS Certificate Manager', short: 'ACM', category: 'security', role: 'cert', layer: 'seguridad', zones: [...OUT_REG], description: 'Certificados TLS gratuitos para CloudFront, ALB y API Gateway.' }),
  S({ id: 'guardduty', name: 'Amazon GuardDuty', short: 'GD', category: 'security', role: 'observability', layer: 'seguridad', zones: [...OUT_REG], description: 'Detección de amenazas sobre logs de la cuenta.' }),

  // ───────── Observabilidad
  S({ id: 'cloudwatch', name: 'Amazon CloudWatch', short: 'CW', category: 'observability', role: 'observability', layer: 'observabilidad', zones: [...OUT_REG], description: 'Logs, métricas, alarmas y dashboards.', inboundProtocol: 'logs/métricas', props: [{ key: 'retention', label: 'Retención de logs (días)', type: 'number', default: 30 }] }),
  S({ id: 'xray', name: 'AWS X‑Ray', short: 'XR', category: 'observability', role: 'observability', layer: 'observabilidad', zones: [...OUT_REG], description: 'Trazas distribuidas.', inboundProtocol: 'trazas' }),
  S({ id: 'cloudtrail', name: 'AWS CloudTrail', short: 'CT', category: 'observability', role: 'observability', layer: 'observabilidad', zones: [...OUT_REG], description: 'Auditoría de llamadas a la API de AWS.' }),

  // ───────── Analítica
  S({ id: 'glue', name: 'AWS Glue', short: 'GLU', category: 'analytics', role: 'analytics', layer: 'datos', zones: [...OUT_REG], description: 'ETL serverless y catálogo de datos.' }),
  S({ id: 'athena', name: 'Amazon Athena', short: 'ATH', category: 'analytics', role: 'analytics', layer: 'datos', zones: [...OUT_REG], description: 'SQL sobre datos en S3.', inboundProtocol: 'SQL' }),
  S({ id: 'redshift', name: 'Amazon Redshift', short: 'RS', category: 'analytics', role: 'datastore', layer: 'datos', zones: ['subnet-data', 'subnet-private'], vpcBound: true, description: 'Data warehouse columnar.', inboundProtocol: 'SQL 5439', props: [DATA_CLASS, { key: 'encrypted', label: 'Cifrado en reposo', type: 'bool', default: true }] }),
  S({ id: 'quicksight', name: 'Amazon QuickSight', short: 'QS', category: 'analytics', role: 'analytics', layer: 'datos', zones: [...OUT_REG], description: 'BI y dashboards.' }),

  // ───────── IA
  S({ id: 'bedrock', name: 'Amazon Bedrock', short: 'BR', category: 'ai', role: 'ai', layer: 'aplicacion', zones: [...OUT_REG], description: 'Modelos fundacionales (LLM) administrados.', inboundProtocol: 'HTTPS (InvokeModel)', props: [{ key: 'model', label: 'Modelo', type: 'text', default: 'anthropic.claude' }, { key: 'guardrails', label: 'Guardrails', type: 'bool', default: true }] }),
  S({ id: 'sagemaker', name: 'Amazon SageMaker', short: 'SM‑AI', category: 'ai', role: 'ai', layer: 'aplicacion', zones: ['outside', 'region', 'subnet-private'], description: 'Entrenamiento y endpoints de modelos ML.', inboundProtocol: 'HTTPS (InvokeEndpoint)' }),

  // ───────── DevOps
  S({ id: 'codepipeline', name: 'AWS CodePipeline', short: 'CP', category: 'devops', role: 'devops', layer: 'aplicacion', zones: [...OUT_REG], description: 'CI/CD: compila, prueba y despliega.' }),
];

export const SERVICE_MAP: Record<string, ServiceDef> = Object.fromEntries(SERVICES.map((s) => [s.id, s]));

export function getService(id: string): ServiceDef {
  return SERVICE_MAP[id] ?? SERVICE_MAP.external;
}

export function defaultProps(defs: PropDef[] | undefined) {
  const out: Record<string, string | number | boolean> = {};
  for (const p of defs ?? []) out[p.key] = p.default;
  return out;
}

export const PLACEMENT_LABEL: Record<string, string> = {
  outside: 'fuera de la VPC (global/regional)',
  region: 'dentro de la región',
  'subnet-public': 'subnet pública',
  'subnet-private': 'subnet privada',
  'subnet-data': 'subnet de datos',
};
