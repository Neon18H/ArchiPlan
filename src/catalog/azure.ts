/**
 * Catálogo de Microsoft Azure.
 *
 * Cada servicio declara `equiv`: el servicio de AWS que cumple el mismo rol. Las reglas de
 * conexión, la validación, la simulación y el modelo de amenazas razonan con ese id
 * "lógico", por eso las propiedades usan las MISMAS claves que su equivalente (con
 * etiquetas propias de Azure). Así todo el motor funciona igual en ambas nubes.
 */
import type { PropDef, ServiceDef } from '../types';

export const DATA_CLASSES = ['Público', 'Interno', 'Confidencial', 'Restringido'] as const;
export const DATA_CLASS: PropDef = { key: 'dataClass', label: 'Clasificación de los datos', type: 'select', default: 'Confidencial', options: [...DATA_CLASSES], help: 'Define el impacto en el modelo de amenazas. Restringido: datos personales, financieros o de salud.' };

const OUT_REG = ['outside', 'region'] as const;
const VNET_APP = ['subnet-private', 'subnet-public'] as const;
const DATA = ['subnet-data', 'subnet-private'] as const;

const A = (d: Omit<ServiceDef, 'provider'>): ServiceDef => ({ ...d, provider: 'azure', zones: [...d.zones] });

export const AZURE_SERVICES: ServiceDef[] = [
  // ───────── Red
  A({ id: 'az-dns', equiv: 'route53', name: 'Azure DNS', short: 'DNS', category: 'networking', role: 'dns', layer: 'borde', zones: ['outside'], description: 'Zonas DNS públicas y privadas administradas.', inboundProtocol: 'DNS', props: [{ key: 'domain', label: 'Dominio', type: 'text', default: 'ejemplo.com' }] }),
  A({ id: 'az-frontdoor', equiv: 'cloudfront', name: 'Azure Front Door', short: 'AFD', category: 'networking', role: 'cdn', layer: 'borde', zones: ['outside'], description: 'CDN global y balanceo L7 con caché, TLS y WAF integrado.', inboundProtocol: 'HTTPS', props: [{ key: 'priceClass', label: 'Nivel', type: 'select', default: 'Premium', options: ['Standard', 'Premium'], help: 'Premium incluye reglas administradas del WAF, Bot Manager y Private Link a los orígenes.' }] }),
  A({ id: 'az-waf', equiv: 'waf', name: 'Azure WAF', short: 'WAF', category: 'security', role: 'waf', layer: 'seguridad', zones: ['outside', 'region'], description: 'Firewall de aplicación web en Front Door o Application Gateway.', props: [
    { key: 'managedRules', label: 'Default Rule Set (OWASP)', type: 'bool', default: true },
    { key: 'sqliRules', label: 'Reglas de inyección SQL (DRS)', type: 'bool', default: true },
    { key: 'botControl', label: 'Bot Manager', type: 'bool', default: false, help: 'Detecta bots maliciosos con inteligencia de amenazas de Microsoft.' },
    { key: 'rateLimit', label: 'Rate limit (req/5 min por IP)', type: 'number', default: 2000 },
  ] }),
  A({ id: 'az-ddos', equiv: 'shield', name: 'Azure DDoS Protection', short: 'DDOS', category: 'security', role: 'waf', layer: 'seguridad', zones: ['outside', 'region'], description: 'Protección DDoS de red con ajuste adaptativo y protección de costos.' }),
  A({ id: 'az-appgw', equiv: 'alb', name: 'Application Gateway', short: 'AGW', category: 'networking', role: 'lb', layer: 'borde', zones: [...VNET_APP], vpcBound: true, description: 'Balanceador L7 regional (v2, autoescalable) con WAF opcional.', inboundProtocol: 'HTTPS', props: [{ key: 'scheme', label: 'Frontend', type: 'select', default: 'internet-facing', options: ['internet-facing', 'internal'] }] }),
  A({ id: 'az-lb', equiv: 'nlb', name: 'Azure Load Balancer', short: 'LB', category: 'networking', role: 'lb', layer: 'borde', zones: [...VNET_APP], vpcBound: true, description: 'Balanceador L4 (TCP/UDP) de alto rendimiento.', inboundProtocol: 'TCP', props: [{ key: 'scheme', label: 'Frontend', type: 'select', default: 'internal', options: ['internet-facing', 'internal'] }] }),
  A({ id: 'az-apim', equiv: 'apigw', name: 'API Management', short: 'APIM', category: 'networking', role: 'api', layer: 'borde', zones: [...OUT_REG], description: 'Gateway de APIs con políticas, cuotas, validación de JWT y portal de desarrolladores.', inboundProtocol: 'HTTPS', props: [{ key: 'type', label: 'Nivel', type: 'select', default: 'Standard v2', options: ['Consumption', 'Basic v2', 'Standard v2', 'Premium v2'] }] }),
  A({ id: 'az-natgw', equiv: 'natgw', name: 'NAT Gateway', short: 'NAT', category: 'networking', role: 'netgw', layer: 'red', zones: ['subnet-public', 'subnet-private'], vpcBound: true, description: 'Salida a Internet con IP fija para las subnets privadas.' }),
  A({ id: 'az-pe', equiv: 'vpce', name: 'Private Endpoint', short: 'PE', category: 'networking', role: 'netgw', layer: 'red', zones: ['subnet-private', 'subnet-data'], vpcBound: true, description: 'IP privada en tu VNet para un servicio PaaS (Storage, SQL, Key Vault…).', props: [{ key: 'service', label: 'Servicio', type: 'select', default: 'blob', options: ['blob', 'sqlServer', 'Sql (Cosmos)', 'vault', 'namespace (Service Bus)', 'registry'] }] }),
  A({ id: 'az-vpngw', equiv: 'vpn', name: 'VPN Gateway', short: 'VPN', category: 'networking', role: 'netgw', layer: 'red', zones: ['region', 'outside'], description: 'Túnel IPsec hacia on‑premise (o ExpressRoute para enlace dedicado).' }),

  // ───────── Cómputo
  A({ id: 'az-vmss', equiv: 'ec2', name: 'Virtual Machine Scale Sets', short: 'VMSS', category: 'compute', role: 'compute', layer: 'aplicacion', zones: [...VNET_APP], vpcBound: true, description: 'Máquinas virtuales idénticas con autoescalado y distribución por zonas.', inboundProtocol: 'HTTP 8080', props: [
    { key: 'instanceType', label: 'Tamaño de VM', type: 'text', default: 'Standard_D2s_v5' },
    { key: 'count', label: 'Instancias', type: 'number', default: 2, min: 1, max: 1000 },
    { key: 'autoscaling', label: 'Autoescalado', type: 'bool', default: true },
  ] }),
  A({ id: 'az-functions', equiv: 'lambda', name: 'Azure Functions', short: 'FN', category: 'compute', role: 'compute', layer: 'aplicacion', zones: ['outside', 'region', 'subnet-private'], description: 'Funciones serverless por eventos (Flex Consumption).', inboundProtocol: 'Invoke', props: [
    { key: 'runtime', label: 'Runtime', type: 'select', default: 'node 20', options: ['node 20', 'python 3.11', 'dotnet 8 isolated', 'java 17'] },
    { key: 'memory', label: 'Memoria por instancia (MB)', type: 'number', default: 2048, min: 512, max: 4096 },
    { key: 'timeout', label: 'Timeout (s)', type: 'number', default: 30, min: 1, max: 600 },
  ] }),
  A({ id: 'az-appservice', equiv: 'apprunner', name: 'App Service', short: 'APP', category: 'compute', role: 'compute', layer: 'aplicacion', zones: [...OUT_REG], description: 'Aplicaciones web y APIs administradas (código o contenedor) con autoescalado.', inboundProtocol: 'HTTPS', props: [{ key: 'sku', label: 'Plan', type: 'select', default: 'P1v3', options: ['B1', 'S1', 'P1v3', 'P2v3', 'P3v3'] }, { key: 'instances', label: 'Instancias', type: 'number', default: 2, min: 1, max: 30 }] }),
  A({ id: 'az-containerapps', equiv: 'ecs', name: 'Azure Container Apps', short: 'ACA', category: 'containers', role: 'compute', layer: 'aplicacion', zones: [...VNET_APP], vpcBound: true, description: 'Contenedores serverless con escalado por HTTP o eventos (KEDA).', inboundProtocol: 'HTTP 8080', props: [
    { key: 'cpu', label: 'CPU (1024 = 1 vCPU)', type: 'number', default: 512 },
    { key: 'memory', label: 'Memoria (MB)', type: 'number', default: 1024 },
    { key: 'desired', label: 'Réplicas mínimas', type: 'number', default: 2, min: 0 },
    { key: 'image', label: 'Imagen', type: 'text', default: 'app:latest' },
  ] }),
  A({ id: 'az-aks', equiv: 'eks', name: 'Azure Kubernetes Service', short: 'AKS', category: 'containers', role: 'compute', layer: 'aplicacion', zones: [...VNET_APP], vpcBound: true, description: 'Kubernetes administrado.', inboundProtocol: 'HTTP', props: [{ key: 'version', label: 'Versión K8s', type: 'text', default: '1.30' }, { key: 'nodes', label: 'Nodos', type: 'number', default: 3, min: 1 }] }),
  A({ id: 'az-acr', equiv: 'ecr', name: 'Azure Container Registry', short: 'ACR', category: 'containers', role: 'registry', layer: 'aplicacion', zones: [...OUT_REG], description: 'Registro privado de imágenes con escaneo (Defender for Containers).', inboundProtocol: 'HTTPS (pull)' }),

  // ───────── Almacenamiento
  A({ id: 'az-blob', equiv: 's3', name: 'Azure Blob Storage', short: 'BLOB', category: 'storage', role: 'storage', layer: 'datos', zones: [...OUT_REG], emitsEvents: true, description: 'Almacenamiento de objetos (archivos, estáticos, data lake con ADLS Gen2).', inboundProtocol: 'HTTPS (Blob API)', props: [
    DATA_CLASS,
    { key: 'public', label: 'Acceso público anónimo', type: 'bool', default: false },
    { key: 'versioning', label: 'Versionado de blobs', type: 'bool', default: true },
    { key: 'encrypted', label: 'Cifrado (SSE)', type: 'bool', default: true },
  ] }),
  A({ id: 'az-files', equiv: 'efs', name: 'Azure Files', short: 'FILES', category: 'storage', role: 'storage', layer: 'datos', zones: ['subnet-private', 'subnet-data'], vpcBound: true, description: 'Recursos compartidos SMB/NFS administrados (acceso por Private Endpoint).', inboundProtocol: 'SMB 445', props: [DATA_CLASS, { key: 'encrypted', label: 'Cifrado', type: 'bool', default: true }] }),

  // ───────── Bases de datos
  A({ id: 'az-sql', equiv: 'rds', name: 'Azure SQL Database', short: 'SQL', category: 'database', role: 'datastore', layer: 'datos', zones: [...DATA], vpcBound: true, description: 'SQL Server administrado (PaaS) con alta disponibilidad integrada.', inboundProtocol: 'SQL', props: [
    DATA_CLASS,
    { key: 'engine', label: 'Motor', type: 'select', default: 'sqlserver', options: ['sqlserver'] },
    { key: 'instanceClass', label: 'SKU (vCores)', type: 'text', default: 'GP_Gen5_2' },
    { key: 'multiAZ', label: 'Redundancia de zona', type: 'bool', default: true },
    { key: 'encrypted', label: 'TDE (cifrado en reposo)', type: 'bool', default: true },
    { key: 'storage', label: 'Tamaño máximo (GB)', type: 'number', default: 50 },
  ] }),
  A({ id: 'az-postgres', equiv: 'rds', name: 'Azure Database for PostgreSQL', short: 'PG', category: 'database', role: 'datastore', layer: 'datos', zones: [...DATA], vpcBound: true, description: 'PostgreSQL Flexible Server con HA redundante por zona.', inboundProtocol: 'SQL', props: [
    DATA_CLASS,
    { key: 'engine', label: 'Motor', type: 'select', default: 'postgres', options: ['postgres', 'mysql'] },
    { key: 'instanceClass', label: 'SKU', type: 'text', default: 'GP_Standard_D2s_v3' },
    { key: 'multiAZ', label: 'Alta disponibilidad (redundancia de zona)', type: 'bool', default: true },
    { key: 'encrypted', label: 'Cifrado en reposo', type: 'bool', default: true },
    { key: 'storage', label: 'Almacenamiento (GB)', type: 'number', default: 64 },
  ] }),
  A({ id: 'az-cosmos', equiv: 'dynamodb', name: 'Azure Cosmos DB', short: 'COSMOS', category: 'database', role: 'datastore', layer: 'datos', zones: [...OUT_REG], emitsEvents: true, description: 'NoSQL distribuida globalmente (API NoSQL, MongoDB, Cassandra…).', inboundProtocol: 'HTTPS (Cosmos API)', props: [
    DATA_CLASS,
    { key: 'billing', label: 'Capacidad', type: 'select', default: 'Autoscale', options: ['Serverless', 'Autoscale', 'Provisioned'] },
    { key: 'ru', label: 'RU/s máximas', type: 'number', default: 4000, min: 400 },
    { key: 'pk', label: 'Partition key', type: 'text', default: '/pk' },
    { key: 'streams', label: 'Change feed', type: 'bool', default: false },
    { key: 'pitr', label: 'Backup continuo (PITR)', type: 'bool', default: true },
  ] }),
  A({ id: 'az-redis', equiv: 'elasticache', name: 'Azure Cache for Redis', short: 'REDIS', category: 'database', role: 'cache', layer: 'datos', zones: [...DATA], vpcBound: true, description: 'Redis administrado para caché y sesiones.', inboundProtocol: 'Redis 6380 (TLS)', props: [
    DATA_CLASS,
    { key: 'nodeType', label: 'SKU', type: 'select', default: 'Standard C1', options: ['Basic C0', 'Standard C1', 'Standard C2', 'Premium P1', 'Premium P2'] },
    { key: 'replicas', label: 'Réplicas', type: 'number', default: 1, min: 0 },
  ] }),
  A({ id: 'az-search', equiv: 'opensearch', name: 'Azure AI Search', short: 'SRCH', category: 'database', role: 'search', layer: 'datos', zones: [...DATA], vpcBound: true, description: 'Búsqueda de texto completo, vectorial e híbrida.', inboundProtocol: 'HTTPS 443', props: [DATA_CLASS, { key: 'instances', label: 'Réplicas', type: 'number', default: 2 }, { key: 'encrypted', label: 'Cifrado en reposo', type: 'bool', default: true }] }),
  A({ id: 'az-synapse', equiv: 'redshift', name: 'Azure Synapse Analytics', short: 'SYN', category: 'analytics', role: 'datastore', layer: 'datos', zones: [...DATA], vpcBound: true, description: 'Data warehouse y analítica a gran escala.', inboundProtocol: 'SQL 1433', props: [DATA_CLASS, { key: 'encrypted', label: 'Cifrado en reposo', type: 'bool', default: true }] }),

  // ───────── Integración
  A({ id: 'az-servicebus', equiv: 'sqs', name: 'Service Bus (cola)', short: 'SB', category: 'integration', role: 'queue', layer: 'integracion', zones: [...OUT_REG], description: 'Cola de mensajes empresarial con sesiones, transacciones y dead‑letter.', inboundProtocol: 'AMQP', props: [
    { key: 'fifo', label: 'Sesiones (orden FIFO)', type: 'bool', default: false },
    { key: 'dlq', label: 'Dead‑letter', type: 'bool', default: true },
    { key: 'visibility', label: 'Lock duration (s)', type: 'number', default: 60 },
  ] }),
  A({ id: 'az-servicebus-topic', equiv: 'sns', name: 'Service Bus (tópico)', short: 'SBT', category: 'integration', role: 'topic', layer: 'integracion', zones: [...OUT_REG], description: 'Pub/sub con suscripciones y filtros.', inboundProtocol: 'AMQP' }),
  A({ id: 'az-eventgrid', equiv: 'eventbridge', name: 'Event Grid', short: 'EG', category: 'integration', role: 'eventbus', layer: 'integracion', zones: [...OUT_REG], description: 'Enrutamiento de eventos con filtros (CloudEvents).', inboundProtocol: 'HTTPS (eventos)', props: [{ key: 'bus', label: 'Nombre del tópico', type: 'text', default: 'app-events' }] }),
  A({ id: 'az-eventhubs', equiv: 'kinesis', name: 'Event Hubs', short: 'EH', category: 'integration', role: 'stream', layer: 'integracion', zones: [...OUT_REG], description: 'Ingesta de streaming a gran escala (compatible con Kafka).', inboundProtocol: 'AMQP / Kafka', props: [{ key: 'mode', label: 'Nivel', type: 'select', default: 'Standard', options: ['Standard', 'Premium'] }, { key: 'units', label: 'Unidades de throughput', type: 'number', default: 2, min: 1 }] }),
  A({ id: 'az-logicapps', equiv: 'stepfunctions', name: 'Logic Apps / Durable Functions', short: 'LA', category: 'integration', role: 'workflow', layer: 'integracion', zones: [...OUT_REG], description: 'Orquestación de flujos y sagas.', inboundProtocol: 'HTTPS', props: [{ key: 'type', label: 'Plan', type: 'select', default: 'Standard', options: ['Consumption', 'Standard'] }] }),

  // ───────── Seguridad e identidad
  A({ id: 'az-entra', equiv: 'cognito', name: 'Microsoft Entra External ID', short: 'ENTRA', category: 'security', role: 'identity', layer: 'seguridad', zones: [...OUT_REG], emitsEvents: true, description: 'Identidad de clientes (CIAM): registro, login, OIDC/OAuth2 y acceso condicional.', inboundProtocol: 'OIDC/HTTPS', props: [{ key: 'mfa', label: 'MFA (acceso condicional)', type: 'select', default: 'OPTIONAL', options: ['OFF', 'OPTIONAL', 'ON'] }] }),
  A({ id: 'az-keyvault', equiv: 'secrets', name: 'Azure Key Vault', short: 'KV', category: 'security', role: 'secrets', layer: 'seguridad', zones: [...OUT_REG], description: 'Secretos, certificados y llaves con RBAC y auditoría.', inboundProtocol: 'HTTPS (Key Vault)', props: [{ key: 'rotation', label: 'Rotación automática', type: 'bool', default: true }] }),
  A({ id: 'az-keyvault-keys', equiv: 'kms', name: 'Key Vault (llaves / Managed HSM)', short: 'HSM', category: 'security', role: 'kms', layer: 'seguridad', zones: [...OUT_REG], description: 'Llaves administradas por el cliente (CMK) para cifrado en reposo.', inboundProtocol: 'HTTPS (Key Vault)' }),
  A({ id: 'az-cert', equiv: 'acm', name: 'Certificados TLS (Key Vault)', short: 'CERT', category: 'security', role: 'cert', layer: 'seguridad', zones: [...OUT_REG], description: 'Certificados TLS administrados para Front Door, Application Gateway y App Service.' }),
  A({ id: 'az-defender', equiv: 'guardduty', name: 'Microsoft Defender for Cloud', short: 'DEF', category: 'security', role: 'observability', layer: 'seguridad', zones: [...OUT_REG], description: 'Postura de seguridad (CSPM) y detección de amenazas en cargas (CWPP).' }),
  A({ id: 'az-sentinel', equiv: 'guardduty', name: 'Microsoft Sentinel', short: 'SENT', category: 'security', role: 'observability', layer: 'seguridad', zones: [...OUT_REG], description: 'SIEM/SOAR en la nube sobre Log Analytics.' }),

  // ───────── Observabilidad
  A({ id: 'az-monitor', equiv: 'cloudwatch', name: 'Azure Monitor (Log Analytics)', short: 'MON', category: 'observability', role: 'observability', layer: 'observabilidad', zones: [...OUT_REG], description: 'Logs, métricas, alertas y workbooks.', inboundProtocol: 'logs/métricas', props: [{ key: 'retention', label: 'Retención de logs (días)', type: 'number', default: 30 }] }),
  A({ id: 'az-appinsights', equiv: 'xray', name: 'Application Insights', short: 'AI', category: 'observability', role: 'observability', layer: 'observabilidad', zones: [...OUT_REG], description: 'APM: trazas distribuidas, dependencias y errores (OpenTelemetry).', inboundProtocol: 'trazas' }),
  A({ id: 'az-activitylog', equiv: 'cloudtrail', name: 'Activity Log', short: 'ALOG', category: 'observability', role: 'observability', layer: 'observabilidad', zones: [...OUT_REG], description: 'Auditoría de operaciones del plano de control de la suscripción.' }),

  // ───────── Analítica
  A({ id: 'az-datafactory', equiv: 'glue', name: 'Azure Data Factory', short: 'ADF', category: 'analytics', role: 'analytics', layer: 'datos', zones: [...OUT_REG], description: 'ETL/ELT e integración de datos.' }),
  A({ id: 'az-databricks', equiv: 'athena', name: 'Azure Databricks', short: 'DBX', category: 'analytics', role: 'analytics', layer: 'datos', zones: [...OUT_REG], description: 'Lakehouse: Spark, SQL y ML sobre el data lake.', inboundProtocol: 'SQL' }),
  A({ id: 'az-fabric', equiv: 'quicksight', name: 'Power BI / Microsoft Fabric', short: 'PBI', category: 'analytics', role: 'analytics', layer: 'datos', zones: [...OUT_REG], description: 'BI, reportes y analítica unificada.' }),

  // ───────── IA
  A({ id: 'az-openai', equiv: 'bedrock', name: 'Azure OpenAI (AI Foundry)', short: 'AOAI', category: 'ai', role: 'ai', layer: 'aplicacion', zones: [...OUT_REG], description: 'Modelos GPT y otros LLM administrados en tu suscripción.', inboundProtocol: 'HTTPS (OpenAI API)', props: [{ key: 'model', label: 'Modelo', type: 'text', default: 'gpt-4o' }, { key: 'guardrails', label: 'Content Safety y Prompt Shields', type: 'bool', default: true }] }),
  A({ id: 'az-ml', equiv: 'sagemaker', name: 'Azure Machine Learning', short: 'AML', category: 'ai', role: 'ai', layer: 'aplicacion', zones: ['outside', 'region', 'subnet-private'], description: 'Entrenamiento y endpoints de modelos ML.', inboundProtocol: 'HTTPS (endpoint)' }),

  // ───────── DevOps
  A({ id: 'az-devops', equiv: 'codepipeline', name: 'Azure DevOps Pipelines', short: 'ADO', category: 'devops', role: 'devops', layer: 'aplicacion', zones: [...OUT_REG], description: 'CI/CD: compila, prueba y despliega.' }),
];

/** Servicio principal de Azure para cada servicio de AWS (para convertir diagramas). */
export const AWS_TO_AZURE: Record<string, string> = {
  route53: 'az-dns',
  cloudfront: 'az-frontdoor',
  waf: 'az-waf',
  shield: 'az-ddos',
  alb: 'az-appgw',
  nlb: 'az-lb',
  apigw: 'az-apim',
  natgw: 'az-natgw',
  vpce: 'az-pe',
  vpn: 'az-vpngw',
  ec2: 'az-vmss',
  lambda: 'az-functions',
  ecs: 'az-containerapps',
  eks: 'az-aks',
  ecr: 'az-acr',
  apprunner: 'az-appservice',
  s3: 'az-blob',
  efs: 'az-files',
  rds: 'az-postgres',
  aurora: 'az-postgres',
  dynamodb: 'az-cosmos',
  documentdb: 'az-cosmos',
  elasticache: 'az-redis',
  opensearch: 'az-search',
  redshift: 'az-synapse',
  sqs: 'az-servicebus',
  sns: 'az-servicebus-topic',
  eventbridge: 'az-eventgrid',
  stepfunctions: 'az-logicapps',
  kinesis: 'az-eventhubs',
  firehose: 'az-eventhubs',
  msk: 'az-eventhubs',
  cognito: 'az-entra',
  secrets: 'az-keyvault',
  kms: 'az-keyvault-keys',
  acm: 'az-cert',
  guardduty: 'az-defender',
  cloudwatch: 'az-monitor',
  xray: 'az-appinsights',
  cloudtrail: 'az-activitylog',
  glue: 'az-datafactory',
  athena: 'az-databricks',
  quicksight: 'az-fabric',
  bedrock: 'az-openai',
  sagemaker: 'az-ml',
  codepipeline: 'az-devops',
};

/** Regiones equivalentes (aproximación por cercanía). */
export const REGION_MAP: Record<string, string> = {
  'us-east-1': 'eastus',
  'us-east-2': 'eastus2',
  'us-west-1': 'westus',
  'us-west-2': 'westus2',
  'sa-east-1': 'brazilsouth',
  'ca-central-1': 'canadacentral',
  'eu-west-1': 'northeurope',
  'eu-central-1': 'germanywestcentral',
  'eu-west-2': 'uksouth',
  'eu-west-3': 'francecentral',
  'ap-southeast-1': 'southeastasia',
  'ap-northeast-1': 'japaneast',
};
