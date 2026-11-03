import { getService } from '../catalog/catalog';
import { byId, isService, isZone, placementOf } from '../lib/graph';
import type { AppEdge, AppNode, ProjectMeta, SecurityGroup, ServiceNode, SgRule } from '../types';
import { scalingOf } from '../scaling/model';
import { effectiveNet, listenersOf, listenPort, originProtocol, targetOf } from '../net/model';

/**
 * Genera un esqueleto de Terraform (provider AWS ~> 5) a partir del diagrama.
 * No pretende ser un despliegue final: es un punto de partida con la red,
 * los recursos, los security groups derivados de las conexiones y TODOs.
 */
export function toTerraform(nodes: AppNode[], edges: AppEdge[], meta: ProjectMeta, securityGroups?: SecurityGroup[], security: Record<string, boolean> = {}): string {
  const map = byId(nodes);
  const services = nodes.filter(isService).filter((n) => getService(n.data.serviceId).provider !== 'azure');
  const zones = nodes.filter(isZone);
  const used = new Set<string>();
  const names = new Map<string, string>();
  const tfName = (n: AppNode) => {
    if (names.has(n.id)) return names.get(n.id)!;
    const base =
      n.data.label
        .normalize('NFD')
        .replace(/[̀-ͯ]/g, '')
        .toLowerCase()
        .replace(/[^a-z0-9]+/g, '_')
        .replace(/^_+|_+$/g, '')
        .replace(/^(\d)/, '_$1') || 'res';
    let name = base.slice(0, 40);
    let i = 2;
    while (used.has(name)) name = `${base.slice(0, 37)}_${i++}`;
    used.add(name);
    names.set(n.id, name);
    return name;
  };
  const q = (s: unknown) => JSON.stringify(String(s ?? ''));
  const out: string[] = [];
  const block = (s: string) => out.push(s.trim() + '\n');
  const def = (n: ServiceNode) => getService(n.data.serviceId);
  const outs = (n: AppNode) => edges.filter((e) => e.source === n.id).map((e) => ({ e, t: map.get(e.target) })).filter((x): x is { e: AppEdge; t: ServiceNode } => isService(x.t));
  const ins = (n: AppNode) => edges.filter((e) => e.target === n.id).map((e) => ({ e, s: map.get(e.source) })).filter((x): x is { e: AppEdge; s: ServiceNode } => isService(x.s));
  const slug = (meta.name || 'arquitectura').normalize('NFD').replace(/[̀-ͯ]/g, '').toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '').slice(0, 24) || 'app';

  const regionZone = zones.find((z) => z.data.zoneKind === 'region');
  const region = String(regionZone?.data.props.region || meta.region || 'us-east-1');
  const vpc = zones.find((z) => z.data.zoneKind === 'vpc');
  const subnetKinds = ['subnet-public', 'subnet-private', 'subnet-data'] as const;
  const hasSubnet = (k: (typeof subnetKinds)[number]) => zones.some((z) => z.data.zoneKind === k);
  const subnetRef = (k: string) => ({ 'subnet-public': 'aws_subnet.public[*].id', 'subnet-private': 'aws_subnet.private[*].id', 'subnet-data': 'aws_subnet.data[*].id' })[k] ?? 'aws_subnet.private[*].id';
  const placement = (n: ServiceNode) => placementOf(n, map);
  const inVpc = (n: ServiceNode) => !!vpc && placement(n).startsWith('subnet-');
  const hasNat = services.some((n) => n.data.serviceId === 'natgw');
  const needsCert = services.some((n) => ['alb', 'nlb'].includes(n.data.serviceId) && listenersOf(n).some((l) => l.protocol === 'HTTPS' || l.protocol === 'TLS'));

  block(`
# ─────────────────────────────────────────────────────────────
# ${meta.name}
# Generado por ArchiPlan el ${new Date().toISOString().slice(0, 10)}
# Esqueleto de infraestructura: revisa cada TODO antes de aplicar.
#   terraform init && terraform plan
# ─────────────────────────────────────────────────────────────

terraform {
  required_version = ">= 1.6"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }${services.some((n) => n.data.serviceId === 'mq') ? `
    random = {
      source  = "hashicorp/random"
      version = "~> 3.6"
    }` : ''}
  }
}

provider "aws" {
  region = var.region
  default_tags {
    tags = local.tags
  }
}

variable "region" {
  type    = string
  default = ${q(region)}
}

variable "project" {
  type    = string
  default = ${q(slug)}
}

variable "environment" {
  type    = string
  default = ${q(meta.environment || 'prod')}
}
${needsCert ? `
variable "certificate_arn" {
  type        = string
  description = "ARN del certificado de ACM para los listeners HTTPS de los balanceadores"
}
` : ''}
locals {
  name = "\${var.project}-\${var.environment}"
  tags = {
    Project     = var.project
    Environment = var.environment
    ManagedBy   = "terraform"
    DesignedIn  = "archiplan"
  }
}

data "aws_availability_zones" "available" {
  state = "available"
}

data "aws_caller_identity" "current" {}
`);

  // ───────── Red
  if (vpc) {
    const azs = Math.max(1, Number(vpc.data.props.azs) || 2);
    block(`
# ═════════════ Red: ${vpc.data.label}
locals {
  az_count = ${azs}
  azs      = slice(data.aws_availability_zones.available.names, 0, local.az_count)
}

resource "aws_vpc" "main" {
  cidr_block           = ${q(vpc.data.props.cidr || '10.0.0.0/16')}
  enable_dns_hostnames = true
  enable_dns_support   = true
  tags = {
    Name = local.name
  }
}
`);
    const offsets: Record<string, number> = { 'subnet-public': 0, 'subnet-private': 10, 'subnet-data': 20 };
    for (const k of subnetKinds) {
      if (!hasSubnet(k)) continue;
      const short = k.replace('subnet-', '');
      block(`
resource "aws_subnet" "${short}" {
  count                   = local.az_count
  vpc_id                  = aws_vpc.main.id
  cidr_block              = cidrsubnet(aws_vpc.main.cidr_block, 8, ${offsets[k]} + count.index)
  availability_zone       = local.azs[count.index]
  map_public_ip_on_launch = ${k === 'subnet-public'}
  tags = {
    Name = "\${local.name}-${short}-\${count.index}"
    Tier = ${q(short)}
  }
}
`);
    }
    if (hasSubnet('subnet-public')) {
      block(`
resource "aws_internet_gateway" "main" {
  vpc_id = aws_vpc.main.id
}

resource "aws_route_table" "public" {
  vpc_id = aws_vpc.main.id
  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.main.id
  }
}

resource "aws_route_table_association" "public" {
  count          = local.az_count
  subnet_id      = aws_subnet.public[count.index].id
  route_table_id = aws_route_table.public.id
}
`);
    }
    if (hasNat && hasSubnet('subnet-public')) {
      block(`
# NAT por AZ para alta disponibilidad (usa count = 1 para ahorrar en desarrollo)
resource "aws_eip" "nat" {
  count  = local.az_count
  domain = "vpc"
}

resource "aws_nat_gateway" "main" {
  count         = local.az_count
  allocation_id = aws_eip.nat[count.index].id
  subnet_id     = aws_subnet.public[count.index].id
  depends_on    = [aws_internet_gateway.main]
}
`);
    }
    for (const k of ['subnet-private', 'subnet-data'] as const) {
      if (!hasSubnet(k)) continue;
      const short = k.replace('subnet-', '');
      const natRoute = hasNat && hasSubnet('subnet-public') && k === 'subnet-private';
      block(`
resource "aws_route_table" "${short}" {
  count  = local.az_count
  vpc_id = aws_vpc.main.id${natRoute ? `
  route {
    cidr_block     = "0.0.0.0/0"
    nat_gateway_id = aws_nat_gateway.main[count.index].id
  }` : ''}
}

resource "aws_route_table_association" "${short}" {
  count          = local.az_count
  subnet_id      = aws_subnet.${short}[count.index].id
  route_table_id = aws_route_table.${short}[count.index].id
}
`);
    }
  }

  // ───────── Security groups (los del arquitecto en modo manual; derivados de las flechas en modo automático)
  const net = effectiveNet(nodes, edges, securityGroups);
  const sgName = new Map<string, string>();
  {
    const usedSg = new Set<string>();
    for (const g of net.groups) {
      const owner = net.mode === 'auto' ? services.find((n) => `sg_${n.id}` === g.id) : undefined;
      let base = owner ? tfName(owner) : g.name.normalize('NFD').replace(/[̀-ͯ]/g, '').toLowerCase().replace(/[^a-z0-9]+/g, '_').replace(/^_+|_+$/g, '').replace(/^(\d)/, '_$1') || 'sg';
      base = base.slice(0, 40);
      let nm = base;
      let i = 2;
      while (usedSg.has(nm)) nm = `${base.slice(0, 37)}_${i++}`;
      usedSg.add(nm);
      sgName.set(g.id, nm);
    }
  }
  const sgOf = (n: ServiceNode) => {
    if (!inVpc(n)) return null;
    const ids = net.sgIdsOf(n).filter((id) => sgName.has(id));
    return ids.length ? ids.map((id) => `aws_security_group.${sgName.get(id)}.id`).join(', ') : null;
  };
  const usesCdnPrefix = net.groups.some((g) => [...g.inbound, ...g.outbound].some((r) => r.peer.kind === 'prefix'));
  const ruleBlock = (g: SecurityGroup, r: SgRule, dir: 'ingress' | 'egress', idx: number) => {
    const gn = sgName.get(g.id)!;
    const peer =
      r.peer.kind === 'sg'
        ? sgName.has(r.peer.sgId)
          ? `referenced_security_group_id = aws_security_group.${sgName.get(r.peer.sgId)}.id`
          : `# TODO: el SG de origen ya no existe\n  cidr_ipv4 = "10.0.0.0/8"`
        : r.peer.kind === 'prefix'
          ? 'prefix_list_id = data.aws_ec2_managed_prefix_list.cloudfront.id'
          : r.peer.value.includes(':')
            ? `cidr_ipv6 = ${q(r.peer.value)}`
            : `cidr_ipv4 = ${q(r.peer.value)}`;
    const ports = r.protocol === 'all' ? '  ip_protocol = "-1"' : `  ip_protocol = ${q(r.protocol)}\n  from_port   = ${r.from}\n  to_port     = ${r.to}`;
    const what = r.protocol === 'all' ? 'all' : r.from === r.to ? String(r.from) : `${r.from}_${r.to}`;
    return `
resource "aws_vpc_security_group_${dir}_rule" "${gn}_${dir === 'ingress' ? 'in' : 'out'}_${what}_${idx}" {
  security_group_id = aws_security_group.${gn}.id
${ports}
  ${peer}${r.description ? `\n  description = ${q(r.description.replace(/[^\x20-\x7E]/g, '').slice(0, 250) || 'regla')}` : ''}
}
`;
  };
  if (net.groups.length && vpc) {
    out.push(`# ═════════════ Security groups (${net.mode === 'manual' ? 'configurados en ArchiPlan' : 'mínimo privilegio a partir de las flechas del diagrama'})\n`);
    if (usesCdnPrefix)
      block(`
data "aws_ec2_managed_prefix_list" "cloudfront" {
  name = "com.amazonaws.global.cloudfront.origin-facing"
}
`);
    for (const g of net.groups) {
      const gn = sgName.get(g.id)!;
      block(`
resource "aws_security_group" "${gn}" {
  name        = "\${local.name}-${gn.replace(/_/g, '-')}"
  description = ${q((g.description || `SG ${g.name}`).replace(/[^\x20-\x7E]/g, '').slice(0, 250) || 'Security group')}
  vpc_id      = aws_vpc.main.id
}
${g.inbound.map((r, i) => ruleBlock(g, r, 'ingress', i + 1)).join('')}${g.outbound.map((r, i) => ruleBlock(g, r, 'egress', i + 1)).join('')}`);
    }
  }

  // ───────── IAM: política mínima por cómputo según sus flechas
  const actionsFor = (t: ServiceNode): [string[], string] | null => {
    const n = tfName(t);
    switch (t.data.serviceId) {
      case 'dynamodb': return [['dynamodb:GetItem', 'dynamodb:PutItem', 'dynamodb:UpdateItem', 'dynamodb:DeleteItem', 'dynamodb:Query'], `aws_dynamodb_table.${n}.arn`];
      case 's3': return [['s3:GetObject', 's3:PutObject'], `"\${aws_s3_bucket.${n}.arn}/*"`];
      case 'sqs': return [['sqs:SendMessage'], `aws_sqs_queue.${n}.arn`];
      case 'sns': return [['sns:Publish'], `aws_sns_topic.${n}.arn`];
      case 'eventbridge': return [['events:PutEvents'], `aws_cloudwatch_event_bus.${n}.arn`];
      case 'secrets': return [['secretsmanager:GetSecretValue'], `aws_secretsmanager_secret.${n}.arn`];
      case 'kinesis': return [['kinesis:PutRecord', 'kinesis:PutRecords'], `aws_kinesis_stream.${n}.arn`];
      case 'stepfunctions': return [['states:StartExecution'], `aws_sfn_state_machine.${n}.arn`];
      case 'bedrock': return [['bedrock:InvokeModel', 'bedrock:InvokeModelWithResponseStream'], '"*"'];
      case 'kms': return [['kms:Encrypt', 'kms:Decrypt', 'kms:GenerateDataKey'], `aws_kms_key.${n}.arn`];
      default: return null;
    }
  };
  const policyFor = (n: ServiceNode) => {
    const stmts = outs(n)
      .map(({ t }) => actionsFor(t))
      .filter((x): x is [string[], string] => !!x)
      .map(([a, r]) => `      {\n        Effect   = "Allow"\n        Action   = ${JSON.stringify(a)}\n        Resource = ${r}\n      }`);
    // Consumir de colas/streams que disparan a esta pieza
    for (const { s } of ins(n)) {
      if (s.data.serviceId === 'sqs') stmts.push(`      {\n        Effect   = "Allow"\n        Action   = ["sqs:ReceiveMessage", "sqs:DeleteMessage", "sqs:GetQueueAttributes"]\n        Resource = aws_sqs_queue.${tfName(s)}.arn\n      }`);
      if (s.data.serviceId === 'kinesis') stmts.push(`      {\n        Effect   = "Allow"\n        Action   = ["kinesis:GetRecords", "kinesis:GetShardIterator", "kinesis:DescribeStream", "kinesis:ListShards"]\n        Resource = aws_kinesis_stream.${tfName(s)}.arn\n      }`);
    }
    return stmts;
  };
  const roleBlock = (name: string, principal: string, n: ServiceNode, managed: string[]) => {
    const stmts = policyFor(n);
    block(`
resource "aws_iam_role" "${name}" {
  name = "\${local.name}-${name.replace(/_/g, '-')}"${security.boundary ? `
  permissions_boundary = aws_iam_policy.app_boundary.arn` : ''}
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = ${q(principal)} }
      Action    = "sts:AssumeRole"
    }]
  })
}
${managed.map((m, i) => `
resource "aws_iam_role_policy_attachment" "${name}_${i}" {
  role       = aws_iam_role.${name}.name
  policy_arn = ${q(m)}
}
`).join('')}${stmts.length ? `
resource "aws_iam_role_policy" "${name}" {
  name = "acceso-derivado-del-diagrama"
  role = aws_iam_role.${name}.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
${stmts.join(',\n')}
    ]
  })
}
` : ''}`);
  };

  // ───────── Recursos por pieza
  const hasEcs = services.some((n) => n.data.serviceId === 'ecs');
  if (hasEcs) {
    block(`
# ═════════════ Contenedores
resource "aws_ecs_cluster" "main" {
  name = local.name
  setting {
    name  = "containerInsights"
    value = "enabled"
  }
}

resource "aws_iam_role" "ecs_execution" {
  name = "\${local.name}-ecs-execution"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "ecs-tasks.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy_attachment" "ecs_execution" {
  role       = aws_iam_role.ecs_execution.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"
}
`);
  }
  const lbTarget = (n: ServiceNode) => ins(n).find(({ s }) => def(s).role === 'lb')?.s;
  const lbTargets = (lb: ServiceNode) => outs(lb).map(({ t }) => t).filter((t) => ['ec2', 'ecs'].includes(t.data.serviceId));
  const tgName = (lb: ServiceNode, t: ServiceNode) => `${tfName(lb)}_${tfName(t)}`;
  const pathOf = (lb: ServiceNode, t: ServiceNode) => {
    const e = edges.find((x) => x.source === lb.id && x.target === t.id);
    const m = String((e?.data as { protocol?: string })?.protocol ?? '').match(/(\/[\w\-/]+)/);
    return m ? `${m[1].replace(/\/$/, '')}*` : `/${tfName(t).replace(/_/g, '-')}*`;
  };
  const dataSubnets = hasSubnet('subnet-data') ? 'aws_subnet.data[*].id' : hasSubnet('subnet-private') ? 'aws_subnet.private[*].id' : null;

  for (const n of services) {
    const name = tfName(n);
    const p = n.data.props;
    const sg = sgOf(n);
    const subnets = inVpc(n) ? subnetRef(placement(n)) : null;
    const header = `# ───── ${n.data.label} (${def(n).name})`;
    switch (n.data.serviceId) {
      case 'route53': {
        const target = outs(n)[0]?.t;
        const alias = target && target.data.serviceId === 'cloudfront' ? `aws_cloudfront_distribution.${tfName(target)}` : target && def(target).role === 'lb' ? `aws_lb.${tfName(target)}` : null;
        block(`
${header}
resource "aws_route53_zone" "${name}" {
  name = ${q(p.domain || 'ejemplo.com')}
}
${alias ? `
resource "aws_route53_record" "${name}_apex" {
  zone_id = aws_route53_zone.${name}.zone_id
  name    = ${q(p.domain || 'ejemplo.com')}
  type    = "A"
  alias {
    name                   = ${alias}.${alias.startsWith('aws_lb') ? 'dns_name' : 'domain_name'}
    zone_id                = ${alias}.${alias.startsWith('aws_lb') ? 'zone_id' : 'hosted_zone_id'}
    evaluate_target_health = ${alias.startsWith('aws_lb')}
  }
}
` : ''}`);
        break;
      }
      case 'cloudfront': {
        const origins = outs(n).filter(({ t }) => ['s3', 'alb', 'nlb', 'apigw'].includes(t.data.serviceId));
        const waf = ins(n).find(({ s }) => s.data.serviceId === 'waf')?.s;
        const first = origins[0]?.t;
        const originBlocks = origins.map(({ t }) => {
          if (t.data.serviceId === 's3')
            return `  origin {\n    origin_id                = ${q(tfName(t))}\n    domain_name              = aws_s3_bucket.${tfName(t)}.bucket_regional_domain_name\n    origin_access_control_id = aws_cloudfront_origin_access_control.${name}.id\n  }`;
          const domain = t.data.serviceId === 'apigw' ? `replace(aws_apigatewayv2_api.${tfName(t)}.api_endpoint, "https://", "")` : `aws_lb.${tfName(t)}.dns_name`;
          return `  origin {\n    origin_id   = ${q(tfName(t))}\n    domain_name = ${domain}\n    custom_origin_config {\n      http_port              = 80\n      https_port             = 443\n      origin_protocol_policy = ${q(originProtocol(n))}\n      origin_ssl_protocols   = ["TLSv1.2"]\n    }\n  }`;
        });
        block(`
${header}
resource "aws_cloudfront_origin_access_control" "${name}" {
  name                              = "\${local.name}-${name.replace(/_/g, '-')}"
  origin_access_control_origin_type = "s3"
  signing_behavior                  = "always"
  signing_protocol                  = "sigv4"
}

resource "aws_cloudfront_distribution" "${name}" {
  enabled         = true
  is_ipv6_enabled = true
  price_class     = ${q(p.priceClass || 'PriceClass_100')}${waf ? `\n  web_acl_id      = aws_wafv2_web_acl.${tfName(waf)}.arn` : ''}
${originBlocks.join('\n') || '  # TODO: conecta CloudFront a un origen (S3, ALB o API Gateway)\n  origin {\n    origin_id   = "todo"\n    domain_name = "example.com"\n    custom_origin_config {\n      http_port              = 80\n      https_port             = 443\n      origin_protocol_policy = "https-only"\n      origin_ssl_protocols   = ["TLSv1.2"]\n    }\n  }'}
  default_cache_behavior {
    target_origin_id       = ${q(first ? tfName(first) : 'todo')}
    viewer_protocol_policy = "redirect-to-https"
    allowed_methods        = ["GET", "HEAD", "OPTIONS"]
    cached_methods         = ["GET", "HEAD"]
    cache_policy_id        = "658327ea-f89d-4fab-a63d-7e88639e58f6" # Managed-CachingOptimized
  }
  restrictions {
    geo_restriction {
      restriction_type = "none"
    }
  }
  viewer_certificate {
    cloudfront_default_certificate = true # TODO: usa ACM (us-east-1) para tu dominio
  }
}
`);
        break;
      }
      case 'waf': {
        const assoc = outs(n).map(({ t }) => t);
        const global = assoc.some((t) => t.data.serviceId === 'cloudfront');
        block(`
${header}
resource "aws_wafv2_web_acl" "${name}" {
  name  = "\${local.name}-${name.replace(/_/g, '-')}"
  scope = ${q(global ? 'CLOUDFRONT' : 'REGIONAL')}${global ? ' # Debe crearse en us-east-1 (usa un provider con alias)' : ''}
  default_action {
    allow {}
  }
${p.managedRules !== false ? `  rule {
    name     = "AWSManagedRulesCommonRuleSet"
    priority = 1
    override_action {
      none {}
    }
    statement {
      managed_rule_group_statement {
        name        = "AWSManagedRulesCommonRuleSet"
        vendor_name = "AWS"
      }
    }
    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "common"
      sampled_requests_enabled   = true
    }
  }
` : ''}${p.sqliRules !== false ? `  rule {
    name     = "AWSManagedRulesSQLiRuleSet"
    priority = 3
    override_action {
      none {}
    }
    statement {
      managed_rule_group_statement {
        name        = "AWSManagedRulesSQLiRuleSet"
        vendor_name = "AWS"
      }
    }
    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "sqli"
      sampled_requests_enabled   = true
    }
  }
` : ''}${p.botControl ? `  rule {
    name     = "AWSManagedRulesBotControlRuleSet"
    priority = 4
    override_action {
      none {}
    }
    statement {
      managed_rule_group_statement {
        name        = "AWSManagedRulesBotControlRuleSet"
        vendor_name = "AWS"
      }
    }
    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "bots"
      sampled_requests_enabled   = true
    }
  }
` : ''}  rule {
    name     = "rate-limit"
    priority = 2
    action {
      block {}
    }
    statement {
      rate_based_statement {
        limit              = ${Number(p.rateLimit) || 2000}
        aggregate_key_type = "IP"
      }
    }
    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "rate"
      sampled_requests_enabled   = true
    }
  }
  visibility_config {
    cloudwatch_metrics_enabled = true
    metric_name                = ${q(name)}
    sampled_requests_enabled   = true
  }
}
${assoc
  .filter((t) => t.data.serviceId === 'alb' || t.data.serviceId === 'apigw')
  .map((t) =>
    t.data.serviceId === 'alb'
      ? `
resource "aws_wafv2_web_acl_association" "${name}_${tfName(t)}" {
  resource_arn = aws_lb.${tfName(t)}.arn
  web_acl_arn  = aws_wafv2_web_acl.${name}.arn
}
`
      : `
# TODO: las HTTP API (apigatewayv2) no soportan WAF directo; usa REST API o CloudFront delante de ${t.data.label}.
`,
  )
  .join('')}`);
        break;
      }
      case 'gwlb': {
        const fws = outs(n).filter(({ t }) => t.data.serviceId === 'ngfw');
        const stick = p.stickiness === '2-tupla' ? 'source_ip_dest_ip' : p.stickiness === '3-tupla' ? 'source_ip_dest_ip_proto' : null;
        const fo = p.targetFailover === false ? 'no_rebalance' : 'rebalance';
        block(`
${header}
resource "aws_lb" "${name}" {
  name                             = substr("\${local.name}-${name.replace(/_/g, '-')}", 0, 32)
  load_balancer_type               = "gateway"
  subnets                          = ${subnets ?? '[] # TODO: subnets de la VPC de inspección'}
  enable_cross_zone_load_balancing = ${!!p.crossZone}
}

resource "aws_lb_target_group" "${name}_fw" {
  name        = substr("\${local.name}-${name.replace(/_/g, '-')}-fw", 0, 32)
  port        = 6081
  protocol    = "GENEVE"
  vpc_id      = aws_vpc.main.id
  target_type = "instance"
  health_check {
    port     = 80
    protocol = "TCP"
  }
  target_failover {
    on_deregistration = "${fo}"
    on_unhealthy      = "${fo}"
  }${stick ? `
  stickiness {
    enabled = true
    type    = "${stick}"
  }` : ''}
}

resource "aws_lb_listener" "${name}" {
  load_balancer_arn = aws_lb.${name}.arn
  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.${name}_fw.arn
  }
}

# Servicio de endpoint: lo consumen los Gateway Load Balancer Endpoints de cada VPC inspeccionada
resource "aws_vpc_endpoint_service" "${name}" {
  acceptance_required        = false
  gateway_load_balancer_arns = [aws_lb.${name}.arn]
}

# Si todos los firewalls fallan el health check, el GWLB les sigue enviando tráfico (fail-open): alarma
resource "aws_cloudwatch_metric_alarm" "${name}_unhealthy" {
  alarm_name          = "\${local.name}-${name.replace(/_/g, '-')}-firewalls-unhealthy"
  namespace           = "AWS/GatewayELB"
  metric_name         = "UnHealthyHostCount"
  statistic           = "Maximum"
  period              = 60
  evaluation_periods  = 1
  threshold           = 0
  comparison_operator = "GreaterThanThreshold"
  dimensions = {
    LoadBalancer = aws_lb.${name}.arn_suffix
    TargetGroup  = aws_lb_target_group.${name}_fw.arn_suffix
  }
}
${fws.length ? '' : `# TODO: conecta ${n.data.label} a la flota de firewalls (NGFW) para registrar sus instancias
`}`);
        break;
      }
      case 'gwlbe': {
        const gw = outs(n).find(({ t }) => t.data.serviceId === 'gwlb')?.t;
        block(`
${header}
resource "aws_vpc_endpoint" "${name}" {
  vpc_id            = aws_vpc.main.id
  vpc_endpoint_type = "GatewayLoadBalancer"
  service_name      = ${gw ? `aws_vpc_endpoint_service.${tfName(gw)}.service_name` : '"" # TODO: conecta este endpoint a un Gateway Load Balancer'}
  subnet_ids        = ${subnets ? `[${subnets}[0]]` : '[] # TODO'}${p.perAz === false ? '' : ' # TODO: crea un endpoint por AZ (uno por subnet)'}
}

# TODO (rutas): para inspeccionar la entrada, asocia una tabla de rutas al Internet Gateway (edge association)
# que envíe hacia la subnet del balanceador vía este endpoint, y la tabla de esa subnet devuelva 0.0.0.0/0 al mismo
# endpoint. Las dos direcciones deben pasar por el MISMO endpoint (simetría) o el firewall descarta la respuesta.
`);
        break;
      }
      case 'ngfw': {
        const gw = services.find((g) => g.data.serviceId === 'gwlb' && outs(g).some(({ t }) => t.id === n.id));
        const sc = scalingOf(n);
        const k = sc?.desired ?? Math.max(1, Number(p.count ?? 2));
        const max = sc && ['cpu', 'requests', 'step'].includes(sc.policy) ? sc.max : k;
        block(`
${header}
variable "${name}_ami_id" {
  type        = string
  description = "AMI del Marketplace de ${String(p.vendor ?? 'firewall')} (${p.license === 'BYOL' ? 'BYOL' : 'PAYG'}) en la región"
}

resource "aws_launch_template" "${name}" {
  name_prefix   = "\${local.name}-${name.replace(/_/g, '-')}-"
  image_id      = var.${name}_ami_id
  instance_type = ${q(p.instanceType || 'c5n.xlarge')}${sg ? `
  vpc_security_group_ids = [${sg}]` : ''}
  metadata_options {
    http_tokens = "required" # IMDSv2
  }
  # TODO: bootstrap del fabricante (p. ej. Palo Alto: init-cfg con plugin-op-commands=aws-gwlb-inspect:enable)
  user_data = base64encode("")
}

resource "aws_autoscaling_group" "${name}" {
  name                = "\${local.name}-${name.replace(/_/g, '-')}"
  min_size            = ${k}
  max_size            = ${Math.max(k, max)}
  desired_capacity    = ${k}
  vpc_zone_identifier = ${subnets ?? '[] # TODO'}
  health_check_type   = "ELB"
  launch_template {
    id      = aws_launch_template.${name}.id
    version = "$Latest"
  }${gw ? `
  target_group_arns   = [aws_lb_target_group.${tfName(gw)}_fw.arn]` : `
  # TODO: conecta un Gateway Load Balancer a ${n.data.label}`}
}
${p.mgmtPublic ? `# ⚠ En ArchiPlan la interfaz de administración tiene IP pública: no la expongas; usa una subnet de gestión privada.
` : ''}`);
        break;
      }
      case 'alb':
      case 'nlb': {
        const isAlb = n.data.serviceId === 'alb';
        block(`
${header}
resource "aws_lb" "${name}" {
  name               = substr("\${local.name}-${name.replace(/_/g, '-')}", 0, 32)
  load_balancer_type = ${q(isAlb ? 'application' : 'network')}
  internal           = ${p.scheme === 'internal'}
  subnets            = ${subnets ?? '[] # TODO: ubícalo en una subnet'}${sg ? `\n  security_groups    = [${sg}]` : ''}
}

${lbTargets(n)
  .map((t, i) => {
    const tg = targetOf(n, t);
    return `
resource "aws_lb_target_group" "${tgName(n, t)}" {
  name        = substr("\${local.name}-${tfName(t).replace(/_/g, '-')}", 0, 32)
  port        = ${tg.port}
  protocol    = ${q(isAlb ? tg.protocol : 'TCP')}
  target_type = ${q(t.data.serviceId === 'ecs' ? 'ip' : 'instance')}
  vpc_id      = aws_vpc.main.id${isAlb ? `
  health_check {
    path    = ${q(tg.healthPath || '/')}
    matcher = "200-399"
  }` : ''}
}
${i > 0 && isAlb ? `
resource "aws_lb_listener_rule" "${tgName(n, t)}" {
  listener_arn = aws_lb_listener.${name}_${(listenersOf(n).find((l) => l.action === 'forward') ?? { port: 443 }).port}.arn
  priority     = ${i * 10}
  action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.${tgName(n, t)}.arn
  }
  condition {
    path_pattern {
      values = [${q(pathOf(n, t))}]
    }
  }
}
` : ''}`;
  })
  .join('')}${!lbTargets(n).length ? `
# TODO: conecta ${n.data.label} a su destino (EC2 / ECS) para generar el target group
` : ''}${listenersOf(n)
  .map((l) => {
    const first = lbTargets(n)[0];
    const tls = l.protocol === 'HTTPS' || l.protocol === 'TLS';
    const action =
      l.action === 'redirect-https'
        ? `  default_action {
    type = "redirect"
    redirect {
      port        = "443"
      protocol    = "HTTPS"
      status_code = "HTTP_301"
    }
  }`
        : first
          ? `  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.${tgName(n, first)}.arn
  }`
          : `  default_action {
    type = "fixed-response"
    fixed_response {
      content_type = "text/plain"
      status_code  = "503"
    }
  }`;
    return `
resource "aws_lb_listener" "${name}_${l.port}" {
  load_balancer_arn = aws_lb.${name}.arn
  port              = ${l.port}
  protocol          = ${q(l.protocol)}${tls ? `
  ssl_policy        = "ELBSecurityPolicy-TLS13-1-2-2021-06"
  certificate_arn   = var.certificate_arn${l.cert ? '' : ' # ⚠ en ArchiPlan este listener está sin certificado'}` : ''}
${action}
}
`;
  })
  .join('')}`);
        break;
      }
      case 'apigw': {
        const fns = outs(n).filter(({ t }) => t.data.serviceId === 'lambda');
        block(`
${header}
resource "aws_apigatewayv2_api" "${name}" {
  name          = "\${local.name}-${name.replace(/_/g, '-')}"
  protocol_type = ${q(p.type === 'WebSocket' ? 'WEBSOCKET' : 'HTTP')}${p.type === 'WebSocket' ? '\n  route_selection_expression = "$request.body.action"' : ''}
}

resource "aws_apigatewayv2_stage" "${name}" {
  api_id      = aws_apigatewayv2_api.${name}.id
  name        = "$default"
  auto_deploy = true
  default_route_settings {
    throttling_rate_limit  = ${scalingOf(n)!.rateLimit}
    throttling_burst_limit = ${scalingOf(n)!.burstLimit}
  }
}
${fns
  .map(
    ({ t }) => `
resource "aws_apigatewayv2_integration" "${name}_${tfName(t)}" {
  api_id                 = aws_apigatewayv2_api.${name}.id
  integration_type       = "AWS_PROXY"
  integration_uri        = aws_lambda_function.${tfName(t)}.invoke_arn
  payload_format_version = "2.0"
}

resource "aws_apigatewayv2_route" "${name}_${tfName(t)}" {
  api_id    = aws_apigatewayv2_api.${name}.id
  route_key = ${q(fns.length > 1 ? `ANY /${tfName(t).replace(/_/g, '-')}/{proxy+}` : 'ANY /{proxy+}')}
  target    = "integrations/\${aws_apigatewayv2_integration.${name}_${tfName(t)}.id}"
}

resource "aws_lambda_permission" "${name}_${tfName(t)}" {
  statement_id  = "AllowApiGateway"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.${tfName(t)}.function_name
  principal     = "apigateway.amazonaws.com"
  source_arn    = "\${aws_apigatewayv2_api.${name}.execution_arn}/*/*"
}
`,
  )
  .join('')}`);
        break;
      }
      case 'lambda': {
        const cw = outs(n).some(({ t }) => t.data.serviceId === 'xray');
        roleBlock(`${name}_role`, 'lambda.amazonaws.com', n, ['arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole', ...(subnets ? ['arn:aws:iam::aws:policy/service-role/AWSLambdaVPCAccessExecutionRole'] : [])]);
        const envs = outs(n)
          .filter(({ t }) => ['dynamodb', 'sqs', 'sns', 's3', 'secrets'].includes(t.data.serviceId))
          .map(({ t }) => {
            const tn = tfName(t);
            const ref = { dynamodb: `aws_dynamodb_table.${tn}.name`, sqs: `aws_sqs_queue.${tn}.url`, sns: `aws_sns_topic.${tn}.arn`, s3: `aws_s3_bucket.${tn}.bucket`, secrets: `aws_secretsmanager_secret.${tn}.arn` }[t.data.serviceId as 'sqs'];
            return `      ${tn.toUpperCase()} = ${ref}`;
          });
        block(`
${header}
resource "aws_lambda_function" "${name}" {
  function_name = "\${local.name}-${name.replace(/_/g, '-')}"
  role          = aws_iam_role.${name}_role.arn
  runtime       = ${q(String(p.runtime).startsWith('go') ? 'provided.al2023' : p.runtime || 'nodejs20.x')}
  handler       = "index.handler"
  filename      = "build/${name}.zip" # TODO: artefacto de tu pipeline
  memory_size   = ${Number(p.memory) || 512}
  timeout       = ${Number(p.timeout) || 30}${Number(p.reservedConcurrency) > 0 ? `\n  reserved_concurrent_executions = ${Number(p.reservedConcurrency)}` : ''}${cw ? `
  tracing_config {
    mode = "Active"
  }` : ''}${subnets ? `
  vpc_config {
    subnet_ids         = ${subnets}
    security_group_ids = [${sg}]
  }` : ''}${envs.length ? `
  environment {
    variables = {
${envs.join('\n')}
    }
  }` : ''}
}

resource "aws_cloudwatch_log_group" "${name}" {
  name              = "/aws/lambda/\${aws_lambda_function.${name}.function_name}"
  retention_in_days = 30
}
`);
        for (const { s } of ins(n)) {
          if (s.data.serviceId === 'sqs' || s.data.serviceId === 'kinesis' || (s.data.serviceId === 'dynamodb' && s.data.props.streams)) {
            const arn = s.data.serviceId === 'sqs' ? `aws_sqs_queue.${tfName(s)}.arn` : s.data.serviceId === 'kinesis' ? `aws_kinesis_stream.${tfName(s)}.arn` : `aws_dynamodb_table.${tfName(s)}.stream_arn`;
            block(`
resource "aws_lambda_event_source_mapping" "${tfName(s)}_to_${name}" {
  event_source_arn = ${arn}
  function_name    = aws_lambda_function.${name}.arn${s.data.serviceId !== 'sqs' ? '\n  starting_position = "LATEST"' : '\n  batch_size       = 10'}
}
`);
          }
        }
        break;
      }
      case 'ec2': {
        const lb = lbTarget(n);
        const sc = scalingOf(n)!;
        const asg = sc.policy !== 'manual';
        const grows = ['cpu', 'requests', 'step'].includes(sc.policy);
        block(`
${header}
data "aws_ami" "${name}" {
  most_recent = true
  owners      = ["amazon"]
  filter {
    name   = "name"
    values = ["al2023-ami-*-x86_64"]
  }
}

resource "aws_launch_template" "${name}" {
  name_prefix   = "\${local.name}-${name.replace(/_/g, '-')}-"
  image_id      = data.aws_ami.${name}.id
  instance_type = ${q(p.instanceType || 't3.medium')}${sg ? `\n  vpc_security_group_ids = [${sg}]` : ''}
  metadata_options {
    http_tokens = "required" # IMDSv2
  }
}
${asg ? `
resource "aws_autoscaling_group" "${name}" {
  name_prefix             = "\${local.name}-${name.replace(/_/g, '-')}-"
  min_size                = ${grows ? sc.min : sc.desired}
  max_size                = ${grows ? sc.max : sc.desired}
  desired_capacity        = ${sc.desired}
  default_instance_warmup = ${sc.warmup}
  vpc_zone_identifier     = ${subnets ?? '[] # TODO'}${lb ? `\n  target_group_arns       = [aws_lb_target_group.${tgName(lb, n)}.arn]` : ''}
  health_check_type       = ${q(lb ? 'ELB' : 'EC2')}
  launch_template {
    id      = aws_launch_template.${name}.id
    version = "$Latest"
  }
}
${sc.policy === 'cpu' ? `
resource "aws_autoscaling_policy" "${name}_cpu" {
  name                   = "${name.replace(/_/g, '-')}-cpu"
  autoscaling_group_name = aws_autoscaling_group.${name}.name
  policy_type            = "TargetTrackingScaling"
  target_tracking_configuration {
    predefined_metric_specification {
      predefined_metric_type = "ASGAverageCPUUtilization"
    }
    target_value = ${sc.targetCpu}
  }
}
` : ''}${sc.policy === 'requests' ? (lb && lb.data.serviceId === 'alb' ? `
resource "aws_autoscaling_policy" "${name}_requests" {
  name                   = "${name.replace(/_/g, '-')}-requests"
  autoscaling_group_name = aws_autoscaling_group.${name}.name
  policy_type            = "TargetTrackingScaling"
  target_tracking_configuration {
    predefined_metric_specification {
      predefined_metric_type = "ALBRequestCountPerTarget"
      resource_label         = "\${aws_lb.${tfName(lb)}.arn_suffix}/\${aws_lb_target_group.${tgName(lb, n)}.arn_suffix}"
    }
    target_value = ${sc.targetRequests * 60} # peticiones por minuto por instancia (${sc.targetRequests} req/s)
  }
}
` : `
# TODO: el escalado por peticiones necesita un ALB delante de ${n.data.label}
`) : ''}${sc.policy === 'step' ? `
resource "aws_autoscaling_policy" "${name}_step" {
  name                      = "${name.replace(/_/g, '-')}-step"
  autoscaling_group_name    = aws_autoscaling_group.${name}.name
  policy_type               = "StepScaling"
  adjustment_type           = "ChangeInCapacity"
  estimated_instance_warmup = ${sc.warmup}
  step_adjustment {
    metric_interval_lower_bound = 0
    scaling_adjustment          = ${sc.stepAdd}
  }
}

resource "aws_cloudwatch_metric_alarm" "${name}_cpu_high" {
  alarm_name          = "\${local.name}-${name.replace(/_/g, '-')}-cpu-alta"
  namespace           = "AWS/EC2"
  metric_name         = "CPUUtilization"
  statistic           = "Average"
  period              = 60
  evaluation_periods  = 2
  threshold           = ${sc.stepThreshold}
  comparison_operator = "GreaterThanThreshold"
  dimensions = {
    AutoScalingGroupName = aws_autoscaling_group.${name}.name
  }
  alarm_actions = [aws_autoscaling_policy.${name}_step.arn]
}
` : ''}` : `
resource "aws_instance" "${name}" {
  count     = ${sc.desired}
  subnet_id = element(${subnets ?? '[] # TODO'}, count.index)
  launch_template {
    id      = aws_launch_template.${name}.id
    version = "$Latest"
  }
}
`}`);
        break;
      }
      case 'ecs': {
        const lb = lbTarget(n);
        roleBlock(`${name}_task`, 'ecs-tasks.amazonaws.com', n, []);
        block(`
${header}
resource "aws_cloudwatch_log_group" "${name}" {
  name              = "/ecs/\${local.name}/${name}"
  retention_in_days = 30
}

resource "aws_ecs_task_definition" "${name}" {
  family                   = "\${local.name}-${name.replace(/_/g, '-')}"
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = ${Number(p.cpu) || 512}
  memory                   = ${Number(p.memory) || 1024}
  execution_role_arn       = aws_iam_role.ecs_execution.arn
  task_role_arn            = aws_iam_role.${name}_task.arn
  container_definitions = jsonencode([{
    name         = ${q(name)}
    image        = ${q(p.image || 'app:latest')} # TODO: URI de ECR
    essential    = true
    portMappings = [{ containerPort = ${listenPort(n)}, protocol = "tcp" }]
    logConfiguration = {
      logDriver = "awslogs"
      options = {
        awslogs-group         = aws_cloudwatch_log_group.${name}.name
        awslogs-region        = var.region
        awslogs-stream-prefix = ${q(name)}
      }
    }
  }])
}

resource "aws_ecs_service" "${name}" {
  name            = ${q(name.replace(/_/g, '-'))}
  cluster         = aws_ecs_cluster.main.id
  task_definition = aws_ecs_task_definition.${name}.arn
  desired_count   = ${scalingOf(n)!.desired}
  launch_type     = "FARGATE"
  network_configuration {
    subnets         = ${subnets ?? '[] # TODO'}
    security_groups = [${sg ?? ''}]
  }${lb ? `
  load_balancer {
    target_group_arn = aws_lb_target_group.${tgName(lb, n)}.arn
    container_name   = ${q(name)}
    container_port   = ${listenPort(n)}
  }` : ''}
}
${(() => {
  const sc = scalingOf(n)!;
  if (!['cpu', 'requests', 'step'].includes(sc.policy)) return '';
  const metric = sc.policy === 'requests' && lb && lb.data.serviceId === 'alb'
    ? `    predefined_metric_specification {
      predefined_metric_type = "ALBRequestCountPerTarget"
      resource_label         = "\${aws_lb.${tfName(lb)}.arn_suffix}/\${aws_lb_target_group.${tgName(lb, n)}.arn_suffix}"
    }`
    : `    predefined_metric_specification {
      predefined_metric_type = "ECSServiceAverageCPUUtilization"
    }`;
  const target = sc.policy === 'requests' && lb ? sc.targetRequests * 60 : sc.policy === 'step' ? sc.stepThreshold : sc.targetCpu;
  return `
resource "aws_appautoscaling_target" "${name}" {
  service_namespace  = "ecs"
  resource_id        = "service/\${aws_ecs_cluster.main.name}/\${aws_ecs_service.${name}.name}"
  scalable_dimension = "ecs:service:DesiredCount"
  min_capacity       = ${sc.min}
  max_capacity       = ${sc.max}
}

resource "aws_appautoscaling_policy" "${name}_scale" {
  name               = "${name.replace(/_/g, '-')}-${sc.policy}"
  policy_type        = "TargetTrackingScaling"
  service_namespace  = aws_appautoscaling_target.${name}.service_namespace
  resource_id        = aws_appautoscaling_target.${name}.resource_id
  scalable_dimension = aws_appautoscaling_target.${name}.scalable_dimension
  target_tracking_scaling_policy_configuration {
    target_value       = ${target}
    scale_out_cooldown = ${sc.warmup}
${metric}
  }
}
`;
})()}`);
        break;
      }
      case 'eks':
        block(`
${header}
# TODO: EKS requiere roles de clúster y de nodos, add-ons y acceso (aws-auth / access entries).
# Recomendado: módulo oficial terraform-aws-modules/eks/aws
# module "${name}" {
#   source          = "terraform-aws-modules/eks/aws"
#   cluster_name    = "\${local.name}-${name}"
#   cluster_version = ${q(p.version || '1.31')}
#   vpc_id          = aws_vpc.main.id
#   subnet_ids      = ${subnets ?? '[]'}
# }
`);
        break;
      case 'ecr':
        block(`
${header}
resource "aws_ecr_repository" "${name}" {
  name                 = "\${var.project}/${name.replace(/_/g, '-')}"
  image_tag_mutability = "IMMUTABLE"
  image_scanning_configuration {
    scan_on_push = true
  }
}
`);
        break;
      case 's3': {
        const cfs = ins(n).filter(({ s }) => s.data.serviceId === 'cloudfront');
        const lambdas = outs(n).filter(({ t }) => t.data.serviceId === 'lambda');
        block(`
${header}
resource "aws_s3_bucket" "${name}" {
  bucket_prefix = "\${var.project}-${name.replace(/_/g, '-').slice(0, 20)}-"
}

resource "aws_s3_bucket_public_access_block" "${name}" {
  bucket                  = aws_s3_bucket.${name}.id
  block_public_acls       = ${!p.public}
  block_public_policy     = ${!p.public}
  ignore_public_acls      = ${!p.public}
  restrict_public_buckets = ${!p.public}
}

resource "aws_s3_bucket_versioning" "${name}" {
  bucket = aws_s3_bucket.${name}.id
  versioning_configuration {
    status = ${q(p.versioning ? 'Enabled' : 'Suspended')}
  }
}
${p.encrypted !== false ? `
resource "aws_s3_bucket_server_side_encryption_configuration" "${name}" {
  bucket = aws_s3_bucket.${name}.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "aws:kms"
    }
  }
}
` : ''}${cfs.length ? `
resource "aws_s3_bucket_policy" "${name}" {
  bucket = aws_s3_bucket.${name}.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "cloudfront.amazonaws.com" }
      Action    = "s3:GetObject"
      Resource  = "\${aws_s3_bucket.${name}.arn}/*"
      Condition = {
        StringEquals = {
          "AWS:SourceArn" = [${cfs.map(({ s }) => `aws_cloudfront_distribution.${tfName(s)}.arn`).join(', ')}]
        }
      }
    }]
  })
}
` : ''}${lambdas.map(({ t }) => `
resource "aws_lambda_permission" "${name}_${tfName(t)}" {
  statement_id  = "AllowS3"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.${tfName(t)}.function_name
  principal     = "s3.amazonaws.com"
  source_arn    = aws_s3_bucket.${name}.arn
}
`).join('')}${lambdas.length ? `
resource "aws_s3_bucket_notification" "${name}" {
  bucket = aws_s3_bucket.${name}.id
${lambdas.map(({ t }) => `  lambda_function {\n    lambda_function_arn = aws_lambda_function.${tfName(t)}.arn\n    events              = ["s3:ObjectCreated:*"]\n  }`).join('\n')}
  depends_on = [${lambdas.map(({ t }) => `aws_lambda_permission.${name}_${tfName(t)}`).join(', ')}]
}
` : ''}`);
        break;
      }
      case 'efs':
        block(`
${header}
resource "aws_efs_file_system" "${name}" {
  encrypted = ${p.encrypted !== false}
}
`);
        break;
      case 'rds':
        block(`
${header}
resource "aws_db_subnet_group" "${name}" {
  name       = "\${local.name}-${name.replace(/_/g, '-')}"
  subnet_ids = ${dataSubnets ?? '[] # TODO'}
}

resource "aws_db_instance" "${name}" {
  identifier                  = "\${local.name}-${name.replace(/_/g, '-')}"
  engine                      = ${q(p.engine || 'postgres')}
  instance_class              = ${q(p.instanceClass || 'db.t4g.medium')}
  allocated_storage           = ${Number(p.storage) || 50}${n.data.net?.port ? `\n  port                        = ${n.data.net.port}` : ''}${security.dbTls ? `\n  parameter_group_name        = aws_db_parameter_group.${name}_tls.name` : ''}${security.dataAuditLogs ? `\n  enabled_cloudwatch_logs_exports = [${String(p.engine || 'postgres').includes('postgres') ? '"postgresql"' : '"audit", "error"'}]` : ''}
  username                    = "app_admin"
  manage_master_user_password = true # contraseña en Secrets Manager con rotación
  multi_az                    = ${p.multiAZ !== false}${p.multiAZ !== false && p.deployment === 'multi-az-cluster' ? ' # Multi-AZ cluster (2 standbys legibles): migrar a aws_rds_cluster con db_cluster_instance_class' : ''}
  storage_encrypted           = ${p.encrypted !== false}
  db_subnet_group_name        = aws_db_subnet_group.${name}.name${sg ? `\n  vpc_security_group_ids      = [${sg}]` : ''}
  backup_retention_period     = ${Math.max(0, Number(p.backupDays ?? 7))}${p.rdsProxy ? '\n  # RDS Proxy: agrega aws_db_proxy + aws_db_proxy_default_target_group apuntando a esta instancia' : ''}${p.crossRegion ? '\n  # DR: crea una réplica en la región secundaria (aws_db_instance con replicate_source_db = this.arn en un provider alias)' : ''}
  deletion_protection         = true
  skip_final_snapshot         = false
  final_snapshot_identifier   = "\${local.name}-${name.replace(/_/g, '-')}-final"
}
`);
        break;
      case 'aurora': {
        const asc = scalingOf(n)!;
        const instances = 1 + (asc.replicas ?? 0);
        block(`
${header}
resource "aws_db_subnet_group" "${name}" {
  name       = "\${local.name}-${name.replace(/_/g, '-')}"
  subnet_ids = ${dataSubnets ?? '[] # TODO'}
}

resource "aws_rds_cluster" "${name}" {
  cluster_identifier          = "\${local.name}-${name.replace(/_/g, '-')}"
  engine                      = ${q(p.engine || 'aurora-postgresql')}${n.data.net?.port ? `\n  port                        = ${n.data.net.port}` : ''}
  master_username             = "app_admin"
  manage_master_user_password = true
  storage_encrypted           = ${p.encrypted !== false}
  db_subnet_group_name        = aws_db_subnet_group.${name}.name${sg ? `\n  vpc_security_group_ids      = [${sg}]` : ''}
  backup_retention_period     = ${Math.max(1, Number(p.backupDays ?? 7))}${p.crossRegion ? '\n  global_cluster_identifier   = null # DR: crea aws_rds_global_cluster y un clúster secundario en la otra región' : ''}
  deletion_protection         = true
  skip_final_snapshot         = false
  final_snapshot_identifier   = "\${local.name}-${name.replace(/_/g, '-')}-final"${asc.serverless ? `
  serverlessv2_scaling_configuration {
    min_capacity = ${asc.minAcu}
    max_capacity = ${asc.maxAcu}
  }` : ''}
}

resource "aws_rds_cluster_instance" "${name}" {
  count              = ${instances}
  identifier         = "\${local.name}-${name.replace(/_/g, '-')}-\${count.index}"
  cluster_identifier = aws_rds_cluster.${name}.id
  engine             = aws_rds_cluster.${name}.engine
  instance_class     = ${q(asc.serverless ? 'db.serverless' : 'db.r6g.large')}
}
`);
        break;
      }
      case 'dynamodb':
        block(`
${header}
resource "aws_dynamodb_table" "${name}" {
  name         = "\${local.name}-${name.replace(/_/g, '-')}"
  billing_mode = ${q(p.billing || 'PAY_PER_REQUEST')}${p.billing === 'PROVISIONED' ? `\n  read_capacity  = ${scalingOf(n)!.rcu}\n  write_capacity = ${Math.max(1, Math.round((scalingOf(n)!.rcu ?? 1000) / 4))}` : ''}
  hash_key     = ${q(p.pk || 'pk')}${p.streams ? '\n  stream_enabled   = true\n  stream_view_type = "NEW_AND_OLD_IMAGES"' : ''}
  attribute {
    name = ${q(p.pk || 'pk')}
    type = "S"
  }
  point_in_time_recovery {
    enabled = ${p.pitr !== false}
  }
  server_side_encryption {
    enabled = true
  }
}
${p.billing === 'PROVISIONED' && scalingOf(n)!.policy === 'cpu' ? `
resource "aws_appautoscaling_target" "${name}_read" {
  service_namespace  = "dynamodb"
  resource_id        = "table/\${aws_dynamodb_table.${name}.name}"
  scalable_dimension = "dynamodb:table:ReadCapacityUnits"
  min_capacity       = ${scalingOf(n)!.rcu}
  max_capacity       = ${scalingOf(n)!.maxRcu}
}

resource "aws_appautoscaling_policy" "${name}_read" {
  name               = "${name.replace(/_/g, '-')}-read"
  policy_type        = "TargetTrackingScaling"
  service_namespace  = aws_appautoscaling_target.${name}_read.service_namespace
  resource_id        = aws_appautoscaling_target.${name}_read.resource_id
  scalable_dimension = aws_appautoscaling_target.${name}_read.scalable_dimension
  target_tracking_scaling_policy_configuration {
    target_value = 70
    predefined_metric_specification {
      predefined_metric_type = "DynamoDBReadCapacityUtilization"
    }
  }
}
` : ''}`);
        break;
      case 'mq':
        block(`
${header}
resource "random_password" "${name}_mq" {
  length  = 24
  special = false
}

resource "aws_mq_broker" "${name}" {
  broker_name                = "\${local.name}-${name.replace(/_/g, '-')}"
  engine_type                = ${q(p.engine || 'RabbitMQ')}
  engine_version             = ${q(p.engine === 'ActiveMQ' ? '5.18' : '3.13')} # TODO: versión soportada
  host_instance_type         = "mq.m5.large"
  deployment_mode            = ${q(p.engine === 'ActiveMQ' ? (p.multiAZ !== false ? 'ACTIVE_STANDBY_MULTI_AZ' : 'SINGLE_INSTANCE') : p.multiAZ !== false ? 'CLUSTER_MULTI_AZ' : 'SINGLE_INSTANCE')}
  publicly_accessible        = false
  auto_minor_version_upgrade = true
  subnet_ids                 = ${p.multiAZ !== false ? (dataSubnets ?? '[] # TODO') : `[element(${dataSubnets ?? '[]'}, 0)]`}${sg ? `\n  security_groups            = [${sg}]` : ''}
  user {
    username = "app"
    password = random_password.${name}_mq.result
  }
}
`);
        break;
      case 'neptune':
        block(`
${header}
resource "aws_neptune_subnet_group" "${name}" {
  name       = "\${local.name}-${name.replace(/_/g, '-')}"
  subnet_ids = ${dataSubnets ?? '[] # TODO'}
}

resource "aws_neptune_cluster" "${name}" {
  cluster_identifier                  = "\${local.name}-${name.replace(/_/g, '-')}"
  engine                              = "neptune"
  storage_encrypted                   = ${p.encrypted !== false}
  iam_database_authentication_enabled = true
  neptune_subnet_group_name           = aws_neptune_subnet_group.${name}.name${sg ? `\n  vpc_security_group_ids              = [${sg}]` : ''}
  backup_retention_period             = 7
  skip_final_snapshot                 = false
  final_snapshot_identifier           = "\${local.name}-${name.replace(/_/g, '-')}-final"
}

resource "aws_neptune_cluster_instance" "${name}" {
  count              = ${Math.max(1, Number(p.instances) || 2)}
  cluster_identifier = aws_neptune_cluster.${name}.id
  instance_class     = "db.r6g.large"
  engine             = "neptune"
}
`);
        break;
      case 'memorydb':
        block(`
${header}
resource "aws_memorydb_subnet_group" "${name}" {
  name       = "\${local.name}-${name.replace(/_/g, '-')}"
  subnet_ids = ${dataSubnets ?? '[] # TODO'}
}

resource "aws_memorydb_cluster" "${name}" {
  name                   = "\${local.name}-${name.replace(/_/g, '-')}"
  node_type              = "db.t4g.small"
  num_shards             = ${Math.max(1, Number(p.shards) || 1)}
  num_replicas_per_shard = ${Math.max(0, Number(p.replicas) || 1)}
  acl_name               = "open-access" # TODO: crea un ACL con usuarios (RBAC)
  tls_enabled            = true
  subnet_group_name      = aws_memorydb_subnet_group.${name}.name${sg ? `\n  security_group_ids     = [${sg}]` : ''}
}
`);
        break;
      case 'keyspaces':
        block(`
${header}
resource "aws_keyspaces_keyspace" "${name}" {
  name = ${q(`${slug.replace(/-/g, '_')}_${name}`.slice(0, 48))}
}
`);
        break;
      case 'timestream':
        block(`
${header}
resource "aws_timestreamwrite_database" "${name}" {
  database_name = "\${local.name}-${name.replace(/_/g, '-')}"
}
`);
        break;
      case 'ses':
        block(`
${header}
variable "ses_domain" {
  type        = string
  description = "Dominio desde el que se envían los correos"
  default     = "example.com"
}

resource "aws_sesv2_email_identity" "${name}" {
  email_identity = var.ses_domain
}
`);
        break;
      case 'appsync':
        block(`
${header}
resource "aws_appsync_graphql_api" "${name}" {
  name                = "\${local.name}-${name.replace(/_/g, '-')}"
  authentication_type = ${q(outs(n).some(({ t }) => t.data.serviceId === 'cognito') ? 'AMAZON_COGNITO_USER_POOLS' : 'AWS_IAM')}${outs(n).some(({ t }) => t.data.serviceId === 'cognito') ? `
  user_pool_config {
    user_pool_id   = aws_cognito_user_pool.${tfName(outs(n).find(({ t }) => t.data.serviceId === 'cognito')!.t)}.id
    default_action = "ALLOW"
  }` : ''}
  schema = <<-EOT
    type Query {
      ping: String
    }
    schema {
      query: Query
    }
  EOT
}
`);
        break;
      case 'globalaccelerator': {
        const targetsGa = outs(n).filter(({ t }) => ['alb', 'nlb', 'ec2'].includes(t.data.serviceId));
        block(`
${header}
resource "aws_globalaccelerator_accelerator" "${name}" {
  name            = "\${local.name}-${name.replace(/_/g, '-')}"
  ip_address_type = "IPV4"
  enabled         = true
}

resource "aws_globalaccelerator_listener" "${name}" {
  accelerator_arn = aws_globalaccelerator_accelerator.${name}.id
  protocol        = "TCP"
  port_range {
    from_port = 443
    to_port   = 443
  }
}
${targetsGa.length ? `
resource "aws_globalaccelerator_endpoint_group" "${name}" {
  listener_arn = aws_globalaccelerator_listener.${name}.id
${targetsGa
  .filter(({ t }) => t.data.serviceId !== 'ec2')
  .map(({ t }) => `  endpoint_configuration {
    endpoint_id                    = aws_lb.${tfName(t)}.arn
    client_ip_preservation_enabled = true
  }`)
  .join('\n')}
}
` : ''}`);
        break;
      }
      case 'transitgw':
        block(`
${header}
resource "aws_ec2_transit_gateway" "${name}" {
  description = ${q(n.data.label)}
}
${vpc ? `
resource "aws_ec2_transit_gateway_vpc_attachment" "${name}" {
  transit_gateway_id = aws_ec2_transit_gateway.${name}.id
  vpc_id             = aws_vpc.main.id
  subnet_ids         = ${hasSubnet('subnet-private') ? 'aws_subnet.private[*].id' : '[] # TODO'}
}
` : ''}`);
        break;
      case 'cloudmap':
        block(`
${header}
resource "aws_service_discovery_private_dns_namespace" "${name}" {
  name = "\${var.project}.internal"
  vpc  = ${vpc ? 'aws_vpc.main.id' : '"" # TODO'}
}
`);
        break;
      case 'inspector':
        if (!security.patching)
          block(`
${header}
data "aws_caller_identity" "inspector" {}

resource "aws_inspector2_enabler" "${name}" {
  account_ids    = [data.aws_caller_identity.inspector.account_id]
  resource_types = ["EC2", "ECR", "LAMBDA"]
}
`);
        break;
      case 'securityhub':
        block(`
${header}
resource "aws_securityhub_account" "${name}" {}

resource "aws_securityhub_standards_subscription" "${name}_fsbp" {
  standards_arn = "arn:aws:securityhub:\${var.region}::standards/aws-foundational-security-best-practices/v/1.0.0"
  depends_on    = [aws_securityhub_account.${name}]
}
`);
        break;
      case 'macie':
        block(`
${header}
resource "aws_macie2_account" "${name}" {}
`);
        break;
      case 'prometheus':
        block(`
${header}
resource "aws_prometheus_workspace" "${name}" {
  alias = "\${local.name}-${name.replace(/_/g, '-')}"
}
`);
        break;
      case 'elasticache':
        block(`
${header}
resource "aws_elasticache_subnet_group" "${name}" {
  name       = "\${local.name}-${name.replace(/_/g, '-')}"
  subnet_ids = ${dataSubnets ?? '[] # TODO'}
}

resource "aws_elasticache_replication_group" "${name}" {
  replication_group_id       = substr("\${local.name}-${name.replace(/_/g, '-')}", 0, 40)
  description                = ${q(n.data.label)}
  engine                     = ${q(p.engine === 'memcached' ? 'redis' : p.engine || 'valkey')}${p.engine === 'memcached' ? ' # TODO: memcached usa aws_elasticache_cluster' : ''}
  node_type                  = ${q(p.nodeType || 'cache.t4g.small')}${n.data.net?.port ? `\n  port                       = ${n.data.net.port}` : ''}
  num_cache_clusters         = ${1 + (Number(p.replicas) || 0)}
  automatic_failover_enabled = ${(Number(p.replicas ?? 1) || 0) > 0 && p.autoFailover !== false}
  multi_az_enabled           = ${(Number(p.replicas ?? 1) || 0) > 0 && p.autoFailover !== false}
  at_rest_encryption_enabled = true
  transit_encryption_enabled = true
  subnet_group_name          = aws_elasticache_subnet_group.${name}.name${sg ? `\n  security_group_ids         = [${sg}]` : ''}
}
`);
        break;
      case 'documentdb':
        block(`
${header}
resource "aws_docdb_subnet_group" "${name}" {
  name       = "\${local.name}-${name.replace(/_/g, '-')}"
  subnet_ids = ${dataSubnets ?? '[] # TODO'}
}

resource "aws_docdb_cluster" "${name}" {
  cluster_identifier          = "\${local.name}-${name.replace(/_/g, '-')}"
  master_username             = "app_admin"
  manage_master_user_password = true
  storage_encrypted           = ${p.encrypted !== false}
  db_subnet_group_name        = aws_docdb_subnet_group.${name}.name${sg ? `\n  vpc_security_group_ids      = [${sg}]` : ''}
}

resource "aws_docdb_cluster_instance" "${name}" {
  count              = ${Number(p.instances) || 2}
  cluster_identifier = aws_docdb_cluster.${name}.id
  instance_class     = "db.t4g.medium"
}
`);
        break;
      case 'opensearch':
        block(`
${header}
resource "aws_opensearch_domain" "${name}" {
  domain_name    = substr(${q(`${slug}-${name.replace(/_/g, '-')}`)}, 0, 28)
  engine_version = "OpenSearch_2.13"
  cluster_config {
    instance_type  = "t3.medium.search"
    instance_count = ${Number(p.instances) || 2}
  }
  ebs_options {
    ebs_enabled = true
    volume_size = 20
  }
  encrypt_at_rest {
    enabled = ${p.encrypted !== false}
  }
  node_to_node_encryption {
    enabled = true
  }${subnets ? `
  vpc_options {
    subnet_ids         = slice(${subnets}, 0, 1)
    security_group_ids = [${sg}]
  }` : ''}
}
`);
        break;
      case 'redshift':
        block(`
${header}
resource "aws_redshift_subnet_group" "${name}" {
  name       = "\${local.name}-${name.replace(/_/g, '-')}"
  subnet_ids = ${dataSubnets ?? '[] # TODO'}
}

resource "aws_redshift_cluster" "${name}" {
  cluster_identifier          = "\${local.name}-${name.replace(/_/g, '-')}"
  node_type                   = "ra3.xlplus"
  master_username             = "app_admin"
  manage_master_password      = true
  encrypted                   = ${p.encrypted !== false}
  cluster_subnet_group_name   = aws_redshift_subnet_group.${name}.name
  skip_final_snapshot         = false
  final_snapshot_identifier   = "\${local.name}-${name.replace(/_/g, '-')}-final"
}
`);
        break;
      case 'sqs': {
        const fifo = !!p.fifo;
        block(`
${header}${p.dlq ? `
resource "aws_sqs_queue" "${name}_dlq" {
  name                      = "\${local.name}-${name.replace(/_/g, '-')}-dlq${fifo ? '.fifo' : ''}"${fifo ? '\n  fifo_queue                = true' : ''}
  message_retention_seconds = 1209600
}
` : ''}
resource "aws_sqs_queue" "${name}" {
  name                       = "\${local.name}-${name.replace(/_/g, '-')}${fifo ? '.fifo' : ''}"${fifo ? '\n  fifo_queue                 = true' : ''}
  visibility_timeout_seconds = ${Number(p.visibility) || 60}
  sqs_managed_sse_enabled    = true${p.dlq ? `
  redrive_policy = jsonencode({
    deadLetterTargetArn = aws_sqs_queue.${name}_dlq.arn
    maxReceiveCount     = 5
  })` : ''}
}
`);
        break;
      }
      case 'sns': {
        const subs = outs(n).filter(({ t }) => t.data.serviceId === 'sqs' || t.data.serviceId === 'lambda');
        block(`
${header}
resource "aws_sns_topic" "${name}" {
  name              = "\${local.name}-${name.replace(/_/g, '-')}"
  kms_master_key_id = "alias/aws/sns"
}
${subs
  .map(({ t }) =>
    t.data.serviceId === 'sqs'
      ? `
resource "aws_sns_topic_subscription" "${name}_${tfName(t)}" {
  topic_arn = aws_sns_topic.${name}.arn
  protocol  = "sqs"
  endpoint  = aws_sqs_queue.${tfName(t)}.arn
}
# TODO: aws_sqs_queue_policy que permita sns.amazonaws.com en ${t.data.label}
`
      : `
resource "aws_sns_topic_subscription" "${name}_${tfName(t)}" {
  topic_arn = aws_sns_topic.${name}.arn
  protocol  = "lambda"
  endpoint  = aws_lambda_function.${tfName(t)}.arn
}
`,
  )
  .join('')}`);
        break;
      }
      case 'eventbridge': {
        const targets = outs(n).filter(({ t }) => ['lambda', 'sqs', 'sns', 'stepfunctions'].includes(t.data.serviceId));
        const arnOf = (t: ServiceNode) => ({ lambda: `aws_lambda_function.${tfName(t)}.arn`, sqs: `aws_sqs_queue.${tfName(t)}.arn`, sns: `aws_sns_topic.${tfName(t)}.arn`, stepfunctions: `aws_sfn_state_machine.${tfName(t)}.arn` })[t.data.serviceId as 'sqs'];
        block(`
${header}
resource "aws_cloudwatch_event_bus" "${name}" {
  name = "\${local.name}-${String(p.bus || name).replace(/[^a-zA-Z0-9-]/g, '-')}"
}
${targets
  .map(
    ({ t }) => `
resource "aws_cloudwatch_event_rule" "${name}_${tfName(t)}" {
  name           = "\${local.name}-to-${tfName(t).replace(/_/g, '-')}"
  event_bus_name = aws_cloudwatch_event_bus.${name}.name
  event_pattern = jsonencode({
    source = ["\${var.project}.app"] # TODO: patrón real del evento
  })
}

resource "aws_cloudwatch_event_target" "${name}_${tfName(t)}" {
  rule           = aws_cloudwatch_event_rule.${name}_${tfName(t)}.name
  event_bus_name = aws_cloudwatch_event_bus.${name}.name
  arn            = ${arnOf(t)}
}
`,
  )
  .join('')}`);
        break;
      }
      case 'stepfunctions':
        roleBlock(`${name}_role`, 'states.amazonaws.com', n, []);
        block(`
${header}
resource "aws_sfn_state_machine" "${name}" {
  name     = "\${local.name}-${name.replace(/_/g, '-')}"
  role_arn = aws_iam_role.${name}_role.arn
  type     = ${q(p.type || 'STANDARD')}
  definition = jsonencode({
    Comment = ${q(n.data.label)}
    StartAt = "Inicio"
    States = {
      Inicio = { Type = "Pass", End = true } # TODO: define los pasos
    }
  })
}
`);
        break;
      case 'kinesis':
        block(`
${header}
resource "aws_kinesis_stream" "${name}" {
  name            = "\${local.name}-${name.replace(/_/g, '-')}"
  encryption_type = "KMS"
  kms_key_id      = "alias/aws/kinesis"
  stream_mode_details {
    stream_mode = ${q(p.mode || 'ON_DEMAND')}
  }${p.mode === 'PROVISIONED' ? '\n  shard_count = 1' : ''}
}
`);
        break;
      case 'firehose': {
        const bucket = outs(n).find(({ t }) => t.data.serviceId === 's3')?.t;
        block(`
${header}
${bucket ? `resource "aws_iam_role" "${name}_role" {
  name = "\${local.name}-${name.replace(/_/g, '-')}"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "firehose.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_kinesis_firehose_delivery_stream" "${name}" {
  name        = "\${local.name}-${name.replace(/_/g, '-')}"
  destination = "extended_s3"
  extended_s3_configuration {
    role_arn   = aws_iam_role.${name}_role.arn
    bucket_arn = aws_s3_bucket.${tfName(bucket)}.arn
    prefix     = "raw/"
  }
}` : '# TODO: conecta Firehose a un bucket S3 para generar el delivery stream'}
`);
        break;
      }
      case 'msk':
        block(`
${header}
resource "aws_msk_cluster" "${name}" {
  cluster_name           = "\${local.name}-${name.replace(/_/g, '-')}"
  kafka_version          = "3.6.0"
  number_of_broker_nodes = ${Number(p.brokers) || 3}
  broker_node_group_info {
    instance_type   = "kafka.m7g.large"
    client_subnets  = ${subnets ?? '[] # TODO'}
    security_groups = [${sg ?? ''}]
  }
}
`);
        break;
      case 'cognito': {
        const triggers = outs(n).filter(({ t }) => t.data.serviceId === 'lambda');
        block(`
${header}
resource "aws_cognito_user_pool" "${name}" {
  name                     = "\${local.name}-${name.replace(/_/g, '-')}"
  mfa_configuration        = ${q(p.mfa || 'OPTIONAL')}
  auto_verified_attributes = ["email"]
  username_attributes      = ["email"]${p.threatProtection ? `
  user_pool_add_ons {
    advanced_security_mode = "ENFORCED" # threat protection: credenciales filtradas y bloqueo adaptativo
  }` : ''}${p.mfa !== 'OFF' ? `
  software_token_mfa_configuration {
    enabled = true
  }` : ''}
  password_policy {
    minimum_length    = 12
    require_lowercase = true
    require_numbers   = true
    require_symbols   = true
    require_uppercase = true
  }${triggers.length ? `
  lambda_config {
    post_confirmation = aws_lambda_function.${tfName(triggers[0].t)}.arn
  }` : ''}
}

resource "aws_cognito_user_pool_client" "${name}" {
  name                = "web"
  user_pool_id        = aws_cognito_user_pool.${name}.id
  generate_secret     = false
  explicit_auth_flows = ["ALLOW_USER_SRP_AUTH", "ALLOW_REFRESH_TOKEN_AUTH"]
}
`);
        break;
      }
      case 'secrets':
        block(`
${header}
resource "aws_secretsmanager_secret" "${name}" {
  name_prefix = "\${local.name}/${name.replace(/_/g, '-')}-"
  description = ${q(n.data.label)}
}
`);
        break;
      case 'kms':
        block(`
${header}
resource "aws_kms_key" "${name}" {
  description         = ${q(n.data.label)}
  enable_key_rotation = true
}
`);
        break;
      case 'acm':
        block(`
${header}
resource "aws_acm_certificate" "${name}" {
  domain_name       = "ejemplo.com" # TODO: tu dominio
  validation_method = "DNS"
  lifecycle {
    create_before_destroy = true
  }
}
`);
        break;
      case 'guardduty':
        block(`
${header}
resource "aws_guardduty_detector" "${name}" {
  enable = true
}
`);
        break;
      case 'cloudwatch': {
        const senders = ins(n).map(({ s }) => s.data.label);
        block(`
${header}
# Fuentes de logs/métricas: ${senders.join(', ') || 'ninguna conectada'}
resource "aws_sns_topic" "${name}_alarms" {
  name = "\${local.name}-alarmas"
}
${ins(n)
  .filter(({ s }) => s.data.serviceId === 'lambda')
  .map(
    ({ s }) => `
resource "aws_cloudwatch_metric_alarm" "${tfName(s)}_errors" {
  alarm_name          = "\${local.name}-${tfName(s).replace(/_/g, '-')}-errores"
  namespace           = "AWS/Lambda"
  metric_name         = "Errors"
  statistic           = "Sum"
  period              = 300
  evaluation_periods  = 1
  threshold           = 5
  comparison_operator = "GreaterThanOrEqualToThreshold"
  dimensions = {
    FunctionName = aws_lambda_function.${tfName(s)}.function_name
  }
  alarm_actions = [aws_sns_topic.${name}_alarms.arn]
}
`,
  )
  .join('')}`);
        break;
      }
      case 'cloudtrail':
        block(`
${header}
# El trail y su bucket se generan en la sección «Seguridad del proyecto» (al final del archivo).
`);
        break;
      case 'vpce': {
        const svcName = String(p.service || 's3');
        const gw = svcName === 's3' || svcName === 'dynamodb';
        block(`
${header}
resource "aws_vpc_endpoint" "${name}" {
  vpc_id            = aws_vpc.main.id
  service_name      = "com.amazonaws.\${var.region}.${svcName}"
  vpc_endpoint_type = ${q(gw ? 'Gateway' : 'Interface')}${gw
    ? `\n  route_table_ids   = ${hasSubnet('subnet-private') ? 'aws_route_table.private[*].id' : '[]'}`
    : `\n  subnet_ids          = ${subnets ?? '[]'}\n  private_dns_enabled = true`}
}
`);
        break;
      }
      case 'glue':
        block(`
${header}
resource "aws_glue_catalog_database" "${name}" {
  name = ${q(`${slug.replace(/-/g, '_')}_${name}`)}
}
`);
        break;
      case 'athena':
        block(`
${header}
resource "aws_athena_workgroup" "${name}" {
  name = "\${local.name}-${name.replace(/_/g, '-')}"
  configuration {
    enforce_workgroup_configuration = true
    # TODO: result_configuration { output_location = "s3://..." }
  }
}
`);
        break;
      case 'natgw':
      case 'igw':
      case 'user':
      case 'admin':
      case 'external':
      case 'onprem':
        break; // la red ya se generó arriba; actores no son infraestructura
      default:
        block(`
${header}
# TODO: ${def(n).name} — sin plantilla automática todavía. Agrega el recurso manualmente.
`);
    }
  }

  // ───────── Salidas
  const outputs: string[] = [];
  if (vpc) outputs.push(`output "vpc_id" {\n  value = aws_vpc.main.id\n}`);
  for (const n of services) {
    const name = tfName(n);
    if (n.data.serviceId === 'alb' || n.data.serviceId === 'nlb') outputs.push(`output "${name}_dns" {\n  value = aws_lb.${name}.dns_name\n}`);
    if (n.data.serviceId === 'cloudfront') outputs.push(`output "${name}_domain" {\n  value = aws_cloudfront_distribution.${name}.domain_name\n}`);
    if (n.data.serviceId === 'apigw') outputs.push(`output "${name}_url" {\n  value = aws_apigatewayv2_api.${name}.api_endpoint\n}`);
  }
  // ───────── Seguridad del proyecto (⚙ en la pestaña Amenazas)
  const hasSid = (x: string) => services.some((n) => n.data.serviceId === x);
  const secBlocks: string[] = [];
  if (security.boundary)
    secBlocks.push(`
# Límite máximo de permisos para los roles de las aplicaciones (permission boundary)
resource "aws_iam_policy" "app_boundary" {
  name        = "\${local.name}-app-boundary"
  description = "Techo de permisos de los roles de la aplicacion"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      { Sid = "PermitirServiciosDeLaApp", Effect = "Allow", Action = ["s3:*", "dynamodb:*", "sqs:*", "sns:*", "events:*", "secretsmanager:GetSecretValue", "kms:Decrypt", "kms:GenerateDataKey", "logs:*", "xray:*", "cloudwatch:PutMetricData", "bedrock:InvokeModel", "states:StartExecution", "lambda:InvokeFunction", "ecr:GetAuthorizationToken", "ecr:BatchGetImage", "ecr:GetDownloadUrlForLayer", "ec2:CreateNetworkInterface", "ec2:DescribeNetworkInterfaces", "ec2:DeleteNetworkInterface", "ssm:GetParameter*"], Resource = "*" },
      { Sid = "NuncaIAMNiOrganizacion", Effect = "Deny", Action = ["iam:*", "organizations:*", "account:*", "cloudtrail:StopLogging", "cloudtrail:DeleteTrail", "guardduty:DeleteDetector"], Resource = "*" }
    ]
  })
}
`);
  if (security.scp)
    secBlocks.push(`
# SCP de guardrails: se adjunta desde la cuenta de administración de AWS Organizations
variable "organization_target_id" {
  type        = string
  description = "ID de la OU o cuenta a la que se adjunta la SCP (deja vacío si no usas Organizations)"
  default     = ""
}

resource "aws_organizations_policy" "guardrails" {
  name = "\${local.name}-guardrails"
  type = "SERVICE_CONTROL_POLICY"
  content = jsonencode({
    Version = "2012-10-17"
    Statement = [
      { Sid = "ProtegerAuditoria", Effect = "Deny", Action = ["cloudtrail:StopLogging", "cloudtrail:DeleteTrail", "guardduty:DeleteDetector", "guardduty:DisassociateFromMasterAccount", "config:StopConfigurationRecorder"], Resource = "*" },
      { Sid = "NoSalirDeLaOrganizacion", Effect = "Deny", Action = ["organizations:LeaveOrganization"], Resource = "*" },
      { Sid = "SoloRegionesAprobadas", Effect = "Deny", NotAction = ["iam:*", "organizations:*", "route53:*", "cloudfront:*", "waf:*", "wafv2:*", "support:*", "sts:*"], Resource = "*", Condition = { StringNotEquals = { "aws:RequestedRegion" = [var.region, "us-east-1"] } } }
    ]
  })
}

resource "aws_organizations_policy_attachment" "guardrails" {
  count     = var.organization_target_id == "" ? 0 : 1
  policy_id = aws_organizations_policy.guardrails.id
  target_id = var.organization_target_id
}
`);
  if (security.logLock || hasSid('cloudtrail'))
    secBlocks.push(`
# Trail de auditoría${security.logLock ? ' con logs inmutables (Object Lock)' : ''}
resource "aws_s3_bucket" "audit_logs" {
  bucket_prefix       = "\${local.name}-audit-"
  object_lock_enabled = ${!!security.logLock}
}
${security.logLock ? `
resource "aws_s3_bucket_object_lock_configuration" "audit_logs" {
  bucket = aws_s3_bucket.audit_logs.id
  rule {
    default_retention {
      mode = "COMPLIANCE"
      days = 365
    }
  }
}
` : ''}
resource "aws_s3_bucket_policy" "audit_logs" {
  bucket = aws_s3_bucket.audit_logs.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      { Sid = "AclCheck", Effect = "Allow", Principal = { Service = "cloudtrail.amazonaws.com" }, Action = "s3:GetBucketAcl", Resource = aws_s3_bucket.audit_logs.arn },
      { Sid = "Write", Effect = "Allow", Principal = { Service = "cloudtrail.amazonaws.com" }, Action = "s3:PutObject", Resource = "\${aws_s3_bucket.audit_logs.arn}/AWSLogs/*", Condition = { StringEquals = { "s3:x-amz-acl" = "bucket-owner-full-control" } } }
    ]
  })
}

resource "aws_cloudtrail" "main" {
  name                          = "\${local.name}-trail"
  s3_bucket_name                = aws_s3_bucket.audit_logs.id
  is_multi_region_trail         = true
  include_global_service_events = true
  enable_log_file_validation    = true
  depends_on                    = [aws_s3_bucket_policy.audit_logs]
}
`);
  if (security.siem)
    secBlocks.push(`
# Hallazgos de seguridad al equipo de respuesta
resource "aws_sns_topic" "security_alerts" {
  name = "\${local.name}-security-alerts"
}

resource "aws_cloudwatch_event_rule" "guardduty_findings" {
  name          = "\${local.name}-guardduty-findings"
  event_pattern = jsonencode({ source = ["aws.guardduty"], "detail-type" = ["GuardDuty Finding"], detail = { severity = [{ numeric = [">=", 4] }] } })
}

resource "aws_cloudwatch_event_target" "guardduty_findings" {
  rule = aws_cloudwatch_event_rule.guardduty_findings.name
  arn  = aws_sns_topic.security_alerts.arn
}

resource "aws_sns_topic_policy" "security_alerts" {
  arn = aws_sns_topic.security_alerts.arn
  policy = jsonencode({
    Version   = "2012-10-17"
    Statement = [{ Effect = "Allow", Principal = { Service = "events.amazonaws.com" }, Action = "sns:Publish", Resource = aws_sns_topic.security_alerts.arn }]
  })
}
`);
  if (security.patching)
    secBlocks.push(`
# Escaneo de vulnerabilidades y parcheo automático
data "aws_caller_identity" "current" {}

resource "aws_inspector2_enabler" "main" {
  account_ids    = [data.aws_caller_identity.current.account_id]
  resource_types = ["EC2", "ECR", "LAMBDA"]
}

resource "aws_ssm_association" "patching" {
  name                = "AWS-RunPatchBaseline"
  schedule_expression = "cron(0 4 ? * SUN *)"
  parameters = {
    Operation = "Install"
  }
  targets {
    key    = "tag:Project"
    values = [var.project]
  }
}
`);
  if (security.offsiteBackup)
    secBlocks.push(`
# Backups con bloqueo (para copiar a otra cuenta/región agrega un copy_action)
resource "aws_backup_vault" "main" {
  name = "\${local.name}-vault"
}

resource "aws_backup_vault_lock_configuration" "main" {
  backup_vault_name  = aws_backup_vault.main.name
  min_retention_days = 7
  max_retention_days = 365
}

resource "aws_backup_plan" "main" {
  name = "\${local.name}-diario"
  rule {
    rule_name         = "diario"
    target_vault_name = aws_backup_vault.main.name
    schedule          = "cron(0 3 * * ? *)"
    lifecycle {
      delete_after = 35
    }
  }
}
`);
  const firstLb = services.find((n) => n.data.serviceId === 'alb');
  if (security.ddosRunbook && firstLb)
    secBlocks.push(`
# Alarma de tráfico anómalo (punto de partida del runbook de DDoS)
resource "aws_cloudwatch_metric_alarm" "traffic_spike" {
  alarm_name          = "\${local.name}-pico-de-trafico"
  namespace           = "AWS/ApplicationELB"
  metric_name         = "RequestCount"
  statistic           = "Sum"
  period              = 60
  evaluation_periods  = 3
  threshold           = 60000 # TODO: ajusta a ~3x tu pico normal por minuto
  comparison_operator = "GreaterThanThreshold"
  dimensions = {
    LoadBalancer = aws_lb.${tfName(firstLb)}.arn_suffix
  }${security.siem ? `
  alarm_actions = [aws_sns_topic.security_alerts.arn]` : ''}
}
`);
  const pgDbs = services.filter((n) => n.data.serviceId === 'rds');
  if (security.dbTls && pgDbs.length)
    secBlocks.push(
      pgDbs
        .map((n) => {
          const eng = String(n.data.props.engine || 'postgres');
          const mysql = eng.includes('mysql') || eng.includes('maria');
          return `
resource "aws_db_parameter_group" "${tfName(n)}_tls" {
  name_prefix = "\${local.name}-${tfName(n).replace(/_/g, '-')}-tls-"
  family      = ${q(mysql ? 'mysql8.0' : 'postgres16')} # TODO: ajusta a la versión del motor
  parameter {
    name  = ${q(mysql ? 'require_secure_transport' : 'rds.force_ssl')}
    value = "1"
  }
}
`;
        })
        .join(''),
    );
  if (secBlocks.length) block('# ═════════════ Seguridad del proyecto\n' + secBlocks.join(''));

  if (outputs.length) block('# ═════════════ Salidas\n' + outputs.join('\n\n'));
  return out.join('\n');
}
