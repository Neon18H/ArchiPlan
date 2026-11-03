import type { Decision } from '../types';
import type { Spec } from '../lib/layout';

export interface Template {
  id: string;
  name: string;
  description: string;
  tags: string[];
  spec: Spec;
  decisions: Omit<Decision, 'id'>[];
}

export const TEMPLATES: Template[] = [
  {
    id: 'web-3-capas',
    name: 'Web clásica en 3 capas',
    description: 'Presentación, aplicación y datos separados por subnets, con CDN, WAF, balanceo, Auto Scaling, caché y BD Multi‑AZ.',
    tags: ['monolito', 'alta disponibilidad', 'EC2'],
    spec: {
      services: [
        { key: 'u', serviceId: 'user', zone: 'global', label: 'Cliente web' },
        { key: 'dns', serviceId: 'route53', zone: 'global' },
        { key: 'cf', serviceId: 'cloudfront', zone: 'global' },
        { key: 'waf', serviceId: 'waf', zone: 'global' },
        { key: 'alb', serviceId: 'alb', zone: 'public' },
        { key: 'nat', serviceId: 'natgw', zone: 'public' },
        { key: 'app', serviceId: 'ec2', zone: 'private', label: 'Servidores de aplicación', props: { count: 2, autoscaling: true } },
        { key: 'db', serviceId: 'rds', zone: 'data', label: 'BD principal' },
        { key: 'cache', serviceId: 'elasticache', zone: 'data', label: 'Caché de sesiones' },
        { key: 's3', serviceId: 's3', zone: 'region', label: 'Estáticos y archivos' },
        { key: 'sm', serviceId: 'secrets', zone: 'region' },
        { key: 'cw', serviceId: 'cloudwatch', zone: 'region' },
      ],
      edges: [
        ['u', 'dns'], ['u', 'cf'], ['dns', 'cf'], ['waf', 'cf'], ['cf', 'alb'], ['cf', 's3'], ['alb', 'app'],
        ['app', 'db'], ['app', 'cache'], ['app', 's3'], ['app', 'sm'], ['app', 'cw'], ['app', 'nat'],
      ],
    },
    decisions: [
      { title: 'Separar la red en subnets pública, privada y de datos', status: 'aceptada', context: 'La aplicación expone una web pública y maneja datos sensibles.', decision: 'Solo el ALB y el NAT viven en subnet pública; la aplicación en privada; la BD en una subnet de datos aislada.', consequences: 'Reduce la superficie de ataque; requiere NAT o VPC Endpoints para salir a Internet.' },
    ],
  },
  {
    id: 'inspeccion-gwlb',
    name: 'Defensa en profundidad con firewall de terceros',
    description: 'Web en 3 capas con un Palo Alto VM‑Series detrás de un Gateway Load Balancer que inspecciona (IPS) el tráfico entre el ALB y la aplicación, además del WAF en el borde.',
    tags: ['GWLB', 'NGFW', 'IPS', 'defensa en profundidad'],
    spec: {
      services: [
        { key: 'u', serviceId: 'user', zone: 'global', label: 'Cliente web' },
        { key: 'dns', serviceId: 'route53', zone: 'global' },
        { key: 'cf', serviceId: 'cloudfront', zone: 'global' },
        { key: 'waf', serviceId: 'waf', zone: 'global' },
        { key: 'alb', serviceId: 'alb', zone: 'public' },
        { key: 'nat', serviceId: 'natgw', zone: 'public' },
        { key: 'gwlbe', serviceId: 'gwlbe', zone: 'private', label: 'Endpoint de inspección' },
        { key: 'gwlb', serviceId: 'gwlb', zone: 'private', label: 'Gateway Load Balancer' },
        { key: 'fw', serviceId: 'ngfw', zone: 'private', label: 'Palo Alto VM‑Series', props: { vendor: 'Palo Alto VM-Series', count: 2, autoscaling: true } },
        { key: 'app', serviceId: 'ec2', zone: 'private', label: 'Servidores de aplicación', props: { count: 2, autoscaling: true } },
        { key: 'db', serviceId: 'rds', zone: 'data', label: 'BD principal' },
        { key: 'cache', serviceId: 'elasticache', zone: 'data', label: 'Caché de sesiones' },
        { key: 's3', serviceId: 's3', zone: 'region', label: 'Estáticos y archivos' },
        { key: 'sm', serviceId: 'secrets', zone: 'region' },
        { key: 'cw', serviceId: 'cloudwatch', zone: 'region' },
        { key: 'gd', serviceId: 'guardduty', zone: 'region' },
      ],
      edges: [
        ['u', 'dns'], ['u', 'cf'], ['dns', 'cf'], ['waf', 'cf'], ['cf', 'alb'], ['alb', 'gwlbe'], ['gwlbe', 'app'], ['gwlbe', 'gwlb'], ['gwlb', 'fw'],
        ['cf', 's3'], ['app', 'db'], ['app', 'cache'], ['app', 's3'], ['app', 'sm'], ['app', 'cw'], ['app', 'nat'], ['fw', 'cw'],
      ],
    },
    decisions: [
      { title: 'Inspección con firewalls de terceros detrás de un Gateway Load Balancer', status: 'propuesta', context: 'El área de seguridad exige un NGFW con IPS, el mismo fabricante que on‑premise y una sola consola de políticas.', decision: 'Palo Alto VM‑Series en un Auto Scaling Group detrás de un Gateway Load Balancer (GENEVE, UDP 6081), con un endpoint en la ruta entre el ALB y la aplicación.', consequences: 'Licencias PAYG y una flota que hay que parchear y escalar (~10 min por instancia nueva). Si todos los firewalls fallan el health check, el GWLB hace fail‑open: alarma sobre UnHealthyHostCount.' },
      { title: 'Inspeccionar después del ALB y no en el borde', status: 'propuesta', context: 'Delante del ALB el tráfico va cifrado (HTTPS) y descifrarlo en el firewall cuesta ~50 % de su capacidad.', decision: 'El endpoint de inspección va entre el ALB (que termina TLS) y la aplicación: el IPS ve el contenido sin descifrar.', consequences: 'El tramo Internet → CloudFront → ALB lo protege el WAF; el IPS ve solo lo que pasa hacia la aplicación.' },
    ],
  },
  {
    id: 'serverless-api',
    name: 'API serverless',
    description: 'API Gateway + Lambda + DynamoDB con autenticación Cognito. Cero servidores, pago por uso.',
    tags: ['serverless', 'Lambda', 'bajo costo'],
    spec: {
      services: [
        { key: 'u', serviceId: 'user', zone: 'global', label: 'App móvil / SPA', props: { channel: 'Móvil' } },
        { key: 'dns', serviceId: 'route53', zone: 'global' },
        { key: 'waf', serviceId: 'waf', zone: 'global' },
        { key: 'api', serviceId: 'apigw', zone: 'region' },
        { key: 'cog', serviceId: 'cognito', zone: 'region' },
        { key: 'fn', serviceId: 'lambda', zone: 'region', label: 'Funciones de negocio' },
        { key: 'ddb', serviceId: 'dynamodb', zone: 'region' },
        { key: 's3', serviceId: 's3', zone: 'region', label: 'Archivos de usuario' },
        { key: 'cw', serviceId: 'cloudwatch', zone: 'region' },
        { key: 'xr', serviceId: 'xray', zone: 'region' },
      ],
      edges: [['u', 'dns'], ['u', 'cog'], ['dns', 'api'], ['waf', 'api'], ['api', 'cog', 'authorizer (JWT)'], ['api', 'fn'], ['fn', 'ddb'], ['fn', 's3'], ['fn', 'cw'], ['fn', 'xr']],
    },
    decisions: [
      { title: 'Serverless con DynamoDB', status: 'aceptada', context: 'Tráfico variable y equipo pequeño sin operación 24/7.', decision: 'API Gateway HTTP + Lambda + DynamoDB on‑demand.', consequences: 'Costo proporcional al uso; hay que diseñar el modelo de datos por patrones de acceso.' },
    ],
  },
  {
    id: 'microservicios',
    name: 'Microservicios en contenedores',
    description: 'Servicios en ECS Fargate detrás de un ALB, con Aurora, caché, mensajería SQS e imágenes en ECR.',
    tags: ['microservicios', 'ECS', 'contenedores'],
    spec: {
      services: [
        { key: 'u', serviceId: 'user', zone: 'global' },
        { key: 'dns', serviceId: 'route53', zone: 'global' },
        { key: 'cf', serviceId: 'cloudfront', zone: 'global' },
        { key: 'waf', serviceId: 'waf', zone: 'global' },
        { key: 'alb', serviceId: 'alb', zone: 'public' },
        { key: 'nat', serviceId: 'natgw', zone: 'public' },
        { key: 'orders', serviceId: 'ecs', zone: 'private', label: 'Servicio Pedidos' },
        { key: 'catalog', serviceId: 'ecs', zone: 'private', label: 'Servicio Catálogo' },
        { key: 'notif', serviceId: 'ecs', zone: 'private', label: 'Servicio Notificaciones', props: { desired: 2 } },
        { key: 'db', serviceId: 'aurora', zone: 'data', label: 'Aurora Pedidos' },
        { key: 'cache', serviceId: 'elasticache', zone: 'data' },
        { key: 'q', serviceId: 'sqs', zone: 'region', label: 'Cola de eventos de pedido', props: { dlq: true } },
        { key: 'cat', serviceId: 'dynamodb', zone: 'region', label: 'Catálogo' },
        { key: 'ecr', serviceId: 'ecr', zone: 'region' },
        { key: 'sm', serviceId: 'secrets', zone: 'region' },
        { key: 'cw', serviceId: 'cloudwatch', zone: 'region' },
      ],
      edges: [
        ['u', 'dns'], ['dns', 'cf'], ['waf', 'cf'], ['cf', 'alb'], ['alb', 'orders', 'HTTPS /pedidos'], ['alb', 'catalog', 'HTTPS /catalogo'],
        ['orders', 'db'], ['orders', 'q'], ['q', 'notif'], ['catalog', 'cat'], ['catalog', 'cache'],
        ['orders', 'sm'], ['ecr', 'orders'], ['ecr', 'catalog'], ['ecr', 'notif'], ['orders', 'cw'], ['catalog', 'cw'], ['notif', 'cw'], ['notif', 'nat'],
      ],
    },
    decisions: [
      { title: 'Base de datos por servicio', status: 'aceptada', context: 'Equipos independientes por dominio.', decision: 'Cada microservicio es dueño de sus datos; se comunican por API y eventos.', consequences: 'Autonomía de despliegue; consistencia eventual entre servicios.' },
    ],
  },
  {
    id: 'event-driven',
    name: 'Orientada a eventos',
    description: 'Productores publican en EventBridge; consumidores desacoplados con SQS, Lambda y Step Functions.',
    tags: ['eventos', 'asíncrono', 'desacoplado'],
    spec: {
      services: [
        { key: 'u', serviceId: 'user', zone: 'global' },
        { key: 'ext', serviceId: 'external', zone: 'global', label: 'Pasarela de pagos', props: { kind: 'Webhook' } },
        { key: 'waf', serviceId: 'waf', zone: 'global' },
        { key: 'api', serviceId: 'apigw', zone: 'region' },
        { key: 'in', serviceId: 'lambda', zone: 'region', label: 'Recepción de órdenes' },
        { key: 'eb', serviceId: 'eventbridge', zone: 'region' },
        { key: 'q1', serviceId: 'sqs', zone: 'region', label: 'Cola facturación', props: { dlq: true } },
        { key: 'q2', serviceId: 'sqs', zone: 'region', label: 'Cola inventario', props: { dlq: true } },
        { key: 'w1', serviceId: 'lambda', zone: 'region', label: 'Facturación' },
        { key: 'w2', serviceId: 'lambda', zone: 'region', label: 'Inventario' },
        { key: 'sfn', serviceId: 'stepfunctions', zone: 'region', label: 'Saga de despacho' },
        { key: 'ddb', serviceId: 'dynamodb', zone: 'region', label: 'Órdenes' },
        { key: 'sns', serviceId: 'sns', zone: 'region', label: 'Notificaciones' },
        { key: 'cw', serviceId: 'cloudwatch', zone: 'region' },
      ],
      edges: [
        ['u', 'api'], ['ext', 'api', 'Webhook HTTPS'], ['waf', 'api'], ['api', 'in'], ['in', 'ddb'], ['in', 'eb'],
        ['eb', 'q1'], ['eb', 'q2'], ['eb', 'sfn'], ['q1', 'w1'], ['q2', 'w2'], ['w1', 'ddb'], ['w2', 'ddb'], ['sfn', 'sns'], ['sns', 'u', 'correo / push'],
        ['in', 'cw'], ['w1', 'cw'], ['w2', 'cw'],
      ],
    },
    decisions: [
      { title: 'Coreografía con EventBridge', status: 'aceptada', context: 'Varios procesos reaccionan a una misma orden.', decision: 'El productor publica "OrdenCreada"; cada consumidor tiene su cola con DLQ.', consequences: 'Se pueden agregar consumidores sin tocar el productor; hay que versionar los esquemas de eventos.' },
    ],
  },
  {
    id: 'sitio-estatico',
    name: 'Sitio estático / SPA',
    description: 'S3 privado servido por CloudFront con certificado TLS, WAF y DNS.',
    tags: ['frontend', 'CDN', 'S3'],
    spec: {
      services: [
        { key: 'u', serviceId: 'user', zone: 'global', label: 'Visitante' },
        { key: 'dns', serviceId: 'route53', zone: 'global' },
        { key: 'cf', serviceId: 'cloudfront', zone: 'global' },
        { key: 'waf', serviceId: 'waf', zone: 'global' },
        { key: 'acm', serviceId: 'acm', zone: 'global' },
        { key: 's3', serviceId: 's3', zone: 'region', label: 'Bucket del sitio' },
        { key: 'cp', serviceId: 'codepipeline', zone: 'region', label: 'CI/CD del sitio' },
        { key: 'cw', serviceId: 'cloudwatch', zone: 'region' },
      ],
      edges: [['u', 'dns'], ['u', 'cf'], ['dns', 'cf'], ['waf', 'cf'], ['acm', 'cf'], ['cf', 's3', 'HTTPS (OAC)'], ['cp', 's3', 'deploy'], ['cf', 'cw']],
    },
    decisions: [],
  },
  {
    id: 'data-pipeline',
    name: 'Pipeline de datos / analítica',
    description: 'Ingesta en streaming, data lake en S3, catálogo con Glue, consultas con Athena y dashboards.',
    tags: ['datos', 'streaming', 'BI'],
    spec: {
      services: [
        { key: 'src', serviceId: 'external', zone: 'global', label: 'Dispositivos / apps', props: { kind: 'API REST' } },
        { key: 'an', serviceId: 'admin', zone: 'global', label: 'Analista' },
        { key: 'api', serviceId: 'apigw', zone: 'region', label: 'API de ingesta' },
        { key: 'kds', serviceId: 'kinesis', zone: 'region' },
        { key: 'fn', serviceId: 'lambda', zone: 'region', label: 'Enriquecimiento' },
        { key: 'fh', serviceId: 'firehose', zone: 'region' },
        { key: 'raw', serviceId: 's3', zone: 'region', label: 'Data lake (raw/curated)' },
        { key: 'glue', serviceId: 'glue', zone: 'region' },
        { key: 'ath', serviceId: 'athena', zone: 'region' },
        { key: 'qs', serviceId: 'quicksight', zone: 'region' },
        { key: 'waf', serviceId: 'waf', zone: 'global' },
        { key: 'cw', serviceId: 'cloudwatch', zone: 'region' },
      ],
      edges: [['src', 'api'], ['waf', 'api'], ['api', 'kds'], ['kds', 'fn'], ['fn', 'fh'], ['fh', 'raw'], ['glue', 'raw', 'crawler/ETL'], ['ath', 'raw', 'consulta'], ['qs', 'ath'], ['an', 'qs'], ['fn', 'cw']],
    },
    decisions: [],
  },
];
