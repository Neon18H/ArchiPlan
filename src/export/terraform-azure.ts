import { getService } from '../catalog/catalog';
import { byId, isService, isZone, placementOf } from '../lib/graph';
import type { AppEdge, AppNode, ConnData, ProjectMeta, SecurityGroup, ServiceNode } from '../types';
import { effectiveNet, listenPort, targetOf } from '../net/model';

/**
 * Esqueleto de Terraform para Azure (provider azurerm ~> 4.0).
 * Igual que el de AWS: red, recursos por pieza, NSG derivados de las flechas,
 * RBAC de mínimo privilegio con identidades administradas y TODOs.
 */
export function toTerraformAzure(nodes: AppNode[], edges: AppEdge[], meta: ProjectMeta, securityGroups?: SecurityGroup[]): string {
  const map = byId(nodes);
  const services = nodes.filter(isService).filter((n) => getService(n.data.serviceId).provider === 'azure');
  const zones = nodes.filter(isZone);
  const ids = new Set(services.map((n) => n.id));
  const E = edges.filter((e) => ids.has(e.source) && ids.has(e.target));
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
    let name = base.slice(0, 32);
    let i = 2;
    while (used.has(name)) name = `${base.slice(0, 29)}_${i++}`;
    used.add(name);
    names.set(n.id, name);
    return name;
  };
  const sid = (n: ServiceNode) => n.data.serviceId;
  const q = (s: unknown) => JSON.stringify(String(s ?? ''));
  const out: string[] = [];
  const block = (s: string) => out.push(s.trim() + '\n');
  const outs = (n: AppNode) => E.filter((e) => e.source === n.id).map((e) => ({ e, t: map.get(e.target) as ServiceNode }));
  const ins = (n: AppNode) => E.filter((e) => e.target === n.id).map((e) => ({ e, s: map.get(e.source) as ServiceNode }));
  const of = (x: string) => services.filter((n) => sid(n) === x);
  const has = (x: string) => of(x).length > 0;
  const slug = (meta.name || 'arquitectura').normalize('NFD').replace(/[̀-ͯ]/g, '').toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '').slice(0, 20) || 'app';
  const alnum = (s: string, max = 24) => s.replace(/[^a-z0-9]/gi, '').toLowerCase().slice(0, max);
  /** Nombre global único (cuentas de almacenamiento, Key Vault, ACR…): proyecto + pieza + sufijo aleatorio. */
  const globalName = (n: AppNode, max: number, dash = false) => {
    const core = dash ? `${slug}-${tfName(n).replace(/_/g, '-')}`.slice(0, max - 7) : alnum(`${slug}${tfName(n)}`, max - 6);
    return `"${core}${dash ? '-' : ''}\${random_string.suffix.result}"`;
  };
  const RG = 'resource_group_name = azurerm_resource_group.main.name';
  const LOC = 'location            = azurerm_resource_group.main.location';

  const region = zones.find((z) => z.data.zoneKind === 'region');
  const location = String(region?.data.props.region || meta.region || 'eastus');
  const vnet = zones.find((z) => z.data.zoneKind === 'vpc');
  const subnetKinds = ['subnet-public', 'subnet-private', 'subnet-data'] as const;
  const hasSubnet = (k: string) => zones.some((z) => z.data.zoneKind === k);
  const placement = (n: ServiceNode) => placementOf(n, map);
  const short = (k: string) => k.replace('subnet-', '');
  const subnetOf = (n: ServiceNode) => (vnet && placement(n).startsWith('subnet-') ? `azurerm_subnet.${short(placement(n))}.id` : null);
  const needsWorkspace = ['az-monitor', 'az-appinsights', 'az-sentinel', 'az-containerapps', 'az-activitylog'].some(has);
  const ddos = of('az-ddos')[0];

  block(`
# ─────────────────────────────────────────────────────────────
# ${meta.name} — Azure
# Generado por ArchiPlan el ${new Date().toISOString().slice(0, 10)}
# Esqueleto de infraestructura: revisa cada TODO antes de aplicar.
#   terraform init && terraform plan -var="subscription_id=<id>"
# ─────────────────────────────────────────────────────────────

terraform {
  required_version = ">= 1.6"
  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 4.0"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.6"
    }
  }
}

provider "azurerm" {
  features {}
  subscription_id = var.subscription_id
}

variable "subscription_id" {
  type        = string
  description = "Suscripción de Azure donde se despliega"
}

variable "location" {
  type    = string
  default = ${q(location)}
}

variable "project" {
  type    = string
  default = ${q(slug)}
}

variable "environment" {
  type    = string
  default = ${q(meta.environment || 'prod')}
}
${has('az-vmss') ? `
variable "ssh_public_key" {
  type        = string
  description = "Llave pública SSH para las VMs"
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

data "azurerm_client_config" "current" {}

resource "random_string" "suffix" {
  length  = 6
  special = false
  upper   = false
}

resource "azurerm_resource_group" "main" {
  name     = "rg-\${local.name}"
  location = var.location
  tags     = local.tags
}
`);

  if (needsWorkspace) {
    const mon = of('az-monitor')[0];
    block(`
resource "azurerm_log_analytics_workspace" "main" {
  name                = "log-\${local.name}"
  ${RG}
  ${LOC}
  sku                 = "PerGB2018"
  retention_in_days   = ${Math.max(30, Number(mon?.data.props.retention) || 30)}
}
`);
  }

  // ───────── Red
  if (ddos) {
    block(`
# ───── ${ddos.data.label} (Azure DDoS Protection)
resource "azurerm_network_ddos_protection_plan" "main" {
  name = "ddos-\${local.name}"
  ${RG}
  ${LOC}
}
`);
  }
  if (vnet) {
    block(`
# ═════════════ Red: ${vnet.data.label}
resource "azurerm_virtual_network" "main" {
  name                = "vnet-\${local.name}"
  ${RG}
  ${LOC}
  address_space       = [${q(vnet.data.props.cidr || '10.0.0.0/16')}]${ddos ? `
  ddos_protection_plan {
    id     = azurerm_network_ddos_protection_plan.main.id
    enable = true
  }` : ''}
}
`);
    const offsets: Record<string, number> = { 'subnet-public': 0, 'subnet-private': 10, 'subnet-data': 20 };
    for (const k of subnetKinds) {
      if (!hasSubnet(k)) continue;
      block(`
resource "azurerm_subnet" "${short(k)}" {
  name                 = "snet-${short(k)}"
  ${RG}
  virtual_network_name = azurerm_virtual_network.main.name
  address_prefixes     = [cidrsubnet(azurerm_virtual_network.main.address_space[0], 8, ${offsets[k]})]
}
`);
    }
    if (has('az-containerapps')) {
      block(`
# Container Apps necesita una subnet dedicada (/23 o mayor) delegada
resource "azurerm_subnet" "aca" {
  name                 = "snet-aca"
  ${RG}
  virtual_network_name = azurerm_virtual_network.main.name
  address_prefixes     = [cidrsubnet(azurerm_virtual_network.main.address_space[0], 7, 20)]
  delegation {
    name = "aca"
    service_delegation {
      name    = "Microsoft.App/environments"
      actions = ["Microsoft.Network/virtualNetworks/subnets/join/action"]
    }
  }
}
`);
    }
    if (of('az-postgres').some((n) => n.data.props.engine !== 'mysql')) {
      block(`
# PostgreSQL Flexible Server con acceso privado: subnet delegada + zona DNS privada
resource "azurerm_subnet" "pg" {
  name                 = "snet-postgres"
  ${RG}
  virtual_network_name = azurerm_virtual_network.main.name
  address_prefixes     = [cidrsubnet(azurerm_virtual_network.main.address_space[0], 8, 30)]
  delegation {
    name = "pg"
    service_delegation {
      name    = "Microsoft.DBforPostgreSQL/flexibleServers"
      actions = ["Microsoft.Network/virtualNetworks/subnets/join/action"]
    }
  }
}

resource "azurerm_private_dns_zone" "pg" {
  name                = "\${local.name}.postgres.database.azure.com"
  ${RG}
}

resource "azurerm_private_dns_zone_virtual_network_link" "pg" {
  name                  = "pg-link"
  ${RG}
  private_dns_zone_name = azurerm_private_dns_zone.pg.name
  virtual_network_id    = azurerm_virtual_network.main.id
}
`);
    }

    // NSG por subnet: en modo manual, unión de las reglas de los NSG configurados; si no, derivados de las flechas
    const netCfg = effectiveNet(nodes, edges, securityGroups);
    let prio = 100;
    for (const k of subnetKinds) {
      if (!hasSubnet(k)) continue;
      const rules: string[] = [];
      const seen = new Set<string>();
      const add = (name: string, src: string, port: string, protocol = 'Tcp') => {
        const key = `${src}|${port}|${protocol}`;
        if (seen.has(key)) return;
        seen.add(key);
        const multi = src.startsWith('[');
        rules.push(`  security_rule {
    name                       = ${q(name.replace(/[^A-Za-z0-9_.-]/g, '-').slice(0, 80))}
    priority                   = ${prio}
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = ${q(protocol)}
    source_port_range          = "*"
    destination_port_range     = ${q(port)}
    ${multi ? 'source_address_prefixes    ' : 'source_address_prefix      '}= ${src}
    destination_address_prefix = "*"
  }`);
        prio += 10;
      };
      const inSubnet = services.filter((n) => placement(n) === k);
      if (netCfg.mode === 'manual') {
        for (const t of inSubnet) {
          if (sid(t) === 'az-appgw') add(`${tfName(t)}-gwmanager`, '"GatewayManager"', '65200-65535');
          for (const g of netCfg.groups.filter((x) => netCfg.sgIdsOf(t).includes(x.id))) {
            g.inbound.forEach((r, i) => {
              let src: string;
              if (r.peer.kind === 'prefix') src = '"AzureFrontDoor.Backend"';
              else if (r.peer.kind === 'cidr') src = r.peer.value.trim() === '0.0.0.0/0' ? '"Internet"' : q(r.peer.value.trim());
              else {
                const sgId = r.peer.sgId;
                const subs = [...new Set(services.filter((n) => netCfg.sgIdsOf(n).includes(sgId)).map((n) => placement(n)).filter((pl) => pl.startsWith('subnet-')))];
                if (!subs.length) return;
                src = subs.length === 1 ? `azurerm_subnet.${short(subs[0])}.address_prefixes[0]` : `[${subs.map((x) => `azurerm_subnet.${short(x)}.address_prefixes[0]`).join(', ')}]`;
              }
              const port = r.protocol === 'all' ? '*' : r.from === r.to ? String(r.from) : `${r.from}-${r.to}`;
              add(`${g.name}-${i + 1}`, src, port, r.protocol === 'all' ? '*' : r.protocol === 'udp' ? 'Udp' : 'Tcp');
            });
          }
        }
      }
      for (const t of netCfg.mode === 'manual' ? [] : inSubnet) {
        if (sid(t) === 'az-appgw') {
          const behindAfd = ins(t).some(({ s }) => sid(s) === 'az-frontdoor');
          add(`${tfName(t)}-https`, behindAfd ? '"AzureFrontDoor.Backend"' : '"Internet"', '443');
          add(`${tfName(t)}-http`, behindAfd ? '"AzureFrontDoor.Backend"' : '"Internet"', '80');
          add(`${tfName(t)}-gwmanager`, '"GatewayManager"', '65200-65535');
          continue;
        }
        for (const { e, s } of ins(t)) {
          const sp = placement(s);
          if (!sp.startsWith('subnet-')) continue;
          const m = String((e.data as ConnData)?.protocol ?? '').match(/(\d{2,5})/);
          const port = t.data.net?.port ? String(t.data.net.port) : m ? m[1] : String(listenPort(t));
          add(`${tfName(s)}-to-${tfName(t)}`, `azurerm_subnet.${short(sp)}.address_prefixes[0]`, port);
        }
      }
      block(`
resource "azurerm_network_security_group" "${short(k)}" {
  name                = "nsg-${short(k)}-\${local.name}"
  ${RG}
  ${LOC}
${rules.join('\n')}
}

resource "azurerm_subnet_network_security_group_association" "${short(k)}" {
  subnet_id                 = azurerm_subnet.${short(k)}.id
  network_security_group_id = azurerm_network_security_group.${short(k)}.id
}
`);
    }
  }

  // ───────── Recursos compartidos
  const sbQueues = services.filter((n) => sid(n) === 'az-servicebus' || sid(n) === 'az-servicebus-topic');
  if (sbQueues.length) {
    block(`
resource "azurerm_servicebus_namespace" "main" {
  name                = "sb-\${local.name}-\${random_string.suffix.result}"
  ${RG}
  ${LOC}
  sku                 = "Standard"
  local_auth_enabled  = false # solo Entra ID (identidades administradas)
  minimum_tls_version = "1.2"
}
`);
  }
  const ehs = of('az-eventhubs');
  if (ehs.length) {
    const premium = ehs.some((n) => n.data.props.mode === 'Premium');
    block(`
resource "azurerm_eventhub_namespace" "main" {
  name                         = "evh-\${local.name}-\${random_string.suffix.result}"
  ${RG}
  ${LOC}
  sku                          = ${q(premium ? 'Premium' : 'Standard')}
  capacity                     = ${Math.max(1, ...ehs.map((n) => Number(n.data.props.units) || 1))}
  local_authentication_enabled = false
  minimum_tls_version          = "1.2"
}
`);
  }
  if (has('az-containerapps')) {
    block(`
resource "azurerm_container_app_environment" "main" {
  name                       = "cae-\${local.name}"
  ${RG}
  ${LOC}
  log_analytics_workspace_id = azurerm_log_analytics_workspace.main.id${vnet ? `
  infrastructure_subnet_id   = azurerm_subnet.aca.id
  zone_redundancy_enabled    = true` : ''}
}
`);
  }

  // ───────── Identidades para RBAC
  const principal = (n: ServiceNode): string | null =>
    ({
      'az-functions': `azurerm_linux_function_app.${tfName(n)}.identity[0].principal_id`,
      'az-appservice': `azurerm_linux_web_app.${tfName(n)}.identity[0].principal_id`,
      'az-containerapps': `azurerm_container_app.${tfName(n)}.identity[0].principal_id`,
      'az-vmss': `azurerm_linux_virtual_machine_scale_set.${tfName(n)}.identity[0].principal_id`,
      'az-aks': `azurerm_kubernetes_cluster.${tfName(n)}.kubelet_identity[0].object_id`,
      'az-logicapps': `azurerm_logic_app_workflow.${tfName(n)}.identity[0].principal_id`,
      'az-datafactory': `azurerm_data_factory.${tfName(n)}.identity[0].principal_id`,
    })[sid(n)] ?? null;
  const roleTarget = (t: ServiceNode, consumer = false): [string, string] | null => {
    const n = tfName(t);
    switch (sid(t)) {
      case 'az-blob':
        return [`azurerm_storage_account.${n}.id`, 'Storage Blob Data Contributor'];
      case 'az-files':
        return [`azurerm_storage_account.${n}.id`, 'Storage File Data SMB Share Contributor'];
      case 'az-keyvault':
        return [`azurerm_key_vault.${n}.id`, 'Key Vault Secrets User'];
      case 'az-keyvault-keys':
        return [`azurerm_key_vault.${n}.id`, 'Key Vault Crypto Service Encryption User'];
      case 'az-servicebus':
        return [`azurerm_servicebus_queue.${n}.id`, consumer ? 'Azure Service Bus Data Receiver' : 'Azure Service Bus Data Sender'];
      case 'az-servicebus-topic':
        return [`azurerm_servicebus_topic.${n}.id`, 'Azure Service Bus Data Sender'];
      case 'az-eventgrid':
        return [`azurerm_eventgrid_topic.${n}.id`, 'EventGrid Data Sender'];
      case 'az-eventhubs':
        return [`azurerm_eventhub.${n}.id`, consumer ? 'Azure Event Hubs Data Receiver' : 'Azure Event Hubs Data Sender'];
      case 'az-openai':
        return [`azurerm_cognitive_account.${n}.id`, 'Cognitive Services OpenAI User'];
      case 'az-search':
        return [`azurerm_search_service.${n}.id`, 'Search Index Data Contributor'];
      case 'az-acr':
        return [`azurerm_container_registry.${n}.id`, 'AcrPull'];
      default:
        return null;
    }
  };
  const roleBlocks: string[] = [];
  const cosmosRoles: string[] = [];
  const dbNotes: string[] = [];
  for (const e of E) {
    const s = map.get(e.source) as ServiceNode;
    const t = map.get(e.target) as ServiceNode;
    // productor/consumidor y pull de imágenes
    const pairs: [ServiceNode, ServiceNode, boolean][] = [];
    if (principal(s)) pairs.push([s, t, false]);
    if (principal(t) && ['az-servicebus', 'az-eventhubs', 'az-acr'].includes(sid(s))) pairs.push([t, s, true]);
    for (const [who, what, consumer] of pairs) {
      const pr = principal(who)!;
      if (sid(what) === 'az-cosmos') {
        cosmosRoles.push(`
resource "azurerm_cosmosdb_sql_role_assignment" "${tfName(who)}_${tfName(what)}" {
  ${RG}
  account_name        = azurerm_cosmosdb_account.${tfName(what)}.name
  role_definition_id  = "\${azurerm_cosmosdb_account.${tfName(what)}.id}/sqlRoleDefinitions/00000000-0000-0000-0000-000000000002" # Data Contributor
  principal_id        = ${pr}
  scope               = azurerm_cosmosdb_account.${tfName(what)}.id
}
`);
        continue;
      }
      if (['az-sql', 'az-postgres'].includes(sid(what))) {
        dbNotes.push(`# ${who.data.label} → ${what.data.label}: crea el usuario de la identidad administrada en la BD (CREATE USER ... FROM EXTERNAL PROVIDER / pgaadauth_create_principal).`);
        continue;
      }
      const rt = roleTarget(what, consumer);
      if (!rt) continue;
      roleBlocks.push(`
resource "azurerm_role_assignment" "${tfName(who)}_${tfName(what)}${consumer ? '_consume' : ''}" {
  scope                = ${rt[0]}
  role_definition_name = ${q(rt[1])}
  principal_id         = ${pr}
}
`);
    }
  }

  // ───────── Recursos por pieza
  const appgwPools = new Map<string, string>();
  for (const n of services) {
    const name = tfName(n);
    const p = n.data.props;
    const header = `# ───── ${n.data.label} (${getService(sid(n)).name})`;
    const subnet = subnetOf(n);
    switch (sid(n)) {
      case 'az-dns':
        block(`
${header}
resource "azurerm_dns_zone" "${name}" {
  name                = ${q(p.domain || 'ejemplo.com')}
  ${RG}
}
# TODO: registro CNAME/alias hacia Front Door o la IP del Application Gateway
`);
        break;
      case 'az-frontdoor': {
        const premium = p.priceClass !== 'Standard';
        const origins = outs(n).filter(({ t }) => ['az-appgw', 'az-apim', 'az-blob', 'az-appservice', 'az-functions', 'az-containerapps'].includes(sid(t)));
        const host = (t: ServiceNode) =>
          ({
            'az-appgw': `azurerm_public_ip.${tfName(t)}.ip_address`,
            'az-apim': `replace(azurerm_api_management.${tfName(t)}.gateway_url, "https://", "")`,
            'az-blob': `azurerm_storage_account.${tfName(t)}.primary_blob_host`,
            'az-appservice': `azurerm_linux_web_app.${tfName(t)}.default_hostname`,
            'az-functions': `azurerm_linux_function_app.${tfName(t)}.default_hostname`,
            'az-containerapps': `azurerm_container_app.${tfName(t)}.ingress[0].fqdn`,
          })[sid(t)]!;
        const waf = ins(n).find(({ s }) => sid(s) === 'az-waf')?.s;
        block(`
${header}
resource "azurerm_cdn_frontdoor_profile" "${name}" {
  name                = "afd-\${local.name}"
  ${RG}
  sku_name            = ${q(premium ? 'Premium_AzureFrontDoor' : 'Standard_AzureFrontDoor')}
}

resource "azurerm_cdn_frontdoor_endpoint" "${name}" {
  name                     = "\${local.name}-\${random_string.suffix.result}"
  cdn_frontdoor_profile_id = azurerm_cdn_frontdoor_profile.${name}.id
}

resource "azurerm_cdn_frontdoor_origin_group" "${name}" {
  name                     = "origins"
  cdn_frontdoor_profile_id = azurerm_cdn_frontdoor_profile.${name}.id
  load_balancing {}
  health_probe {
    path                = "/"
    protocol            = "Https"
    interval_in_seconds = 60
    request_type        = "HEAD"
  }
}
${(origins.length ? origins : [])
  .map(
    ({ t }) => `
resource "azurerm_cdn_frontdoor_origin" "${name}_${tfName(t)}" {
  name                           = ${q(tfName(t).replace(/_/g, '-'))}
  cdn_frontdoor_origin_group_id  = azurerm_cdn_frontdoor_origin_group.${name}.id
  enabled                        = true
  host_name                      = ${host(t)}
  origin_host_header             = ${host(t)}
  certificate_name_check_enabled = ${sid(t) !== 'az-appgw'}
  http_port                      = 80
  https_port                     = 443
}
`,
  )
  .join('')}${origins.length ? `
resource "azurerm_cdn_frontdoor_route" "${name}" {
  name                          = "default"
  cdn_frontdoor_endpoint_id     = azurerm_cdn_frontdoor_endpoint.${name}.id
  cdn_frontdoor_origin_group_id = azurerm_cdn_frontdoor_origin_group.${name}.id
  cdn_frontdoor_origin_ids      = [${origins.map(({ t }) => `azurerm_cdn_frontdoor_origin.${name}_${tfName(t)}.id`).join(', ')}]
  supported_protocols           = ["Http", "Https"]
  patterns_to_match             = ["/*"]
  forwarding_protocol           = "HttpsOnly"
  https_redirect_enabled        = true
  link_to_default_domain        = true
}
` : '# TODO: conecta Front Door a un origen (Application Gateway, App Service, Blob…)\n'}${waf ? `
resource "azurerm_cdn_frontdoor_firewall_policy" "${tfName(waf)}" {
  name                = ${q(alnum(`${slug}${tfName(waf)}`, 60) || 'wafpolicy')}
  ${RG}
  sku_name            = azurerm_cdn_frontdoor_profile.${name}.sku_name
  mode                = "Prevention"
${premium && waf.data.props.managedRules !== false ? `
  managed_rule {
    type    = "Microsoft_DefaultRuleSet"
    version = "2.1"
    action  = "Block"
  }
` : ''}${premium && waf.data.props.botControl ? `
  managed_rule {
    type    = "Microsoft_BotManagerRuleSet"
    version = "1.1"
    action  = "Block"
  }
` : ''}
  custom_rule {
    name                           = "RateLimitPorIP"
    type                           = "RateLimitRule"
    priority                       = 1
    action                         = "Block"
    rate_limit_duration_in_minutes = 5
    rate_limit_threshold           = ${Number(waf.data.props.rateLimit) || 2000}
    match_condition {
      match_variable     = "RemoteAddr"
      operator           = "IPMatch"
      negation_condition = true
      match_values       = ["127.0.0.1"]
    }
  }
}

resource "azurerm_cdn_frontdoor_security_policy" "${name}" {
  name                     = "waf"
  cdn_frontdoor_profile_id = azurerm_cdn_frontdoor_profile.${name}.id
  security_policies {
    firewall {
      cdn_frontdoor_firewall_policy_id = azurerm_cdn_frontdoor_firewall_policy.${tfName(waf)}.id
      association {
        domain {
          cdn_frontdoor_domain_id = azurerm_cdn_frontdoor_endpoint.${name}.id
        }
        patterns_to_match = ["/*"]
      }
    }
  }
}
` : ''}`);
        break;
      }
      case 'az-waf': {
        const appgws = outs(n).filter(({ t }) => sid(t) === 'az-appgw');
        const others = outs(n).filter(({ t }) => !['az-appgw', 'az-frontdoor'].includes(sid(t)));
        if (appgws.length) {
          block(`
${header}
resource "azurerm_web_application_firewall_policy" "${name}" {
  name                = "waf-\${local.name}"
  ${RG}
  ${LOC}
  policy_settings {
    enabled = true
    mode    = "Prevention"
  }
  managed_rules {${p.managedRules !== false ? `
    managed_rule_set {
      type    = "OWASP"
      version = "3.2"
    }` : ''}${p.botControl ? `
    managed_rule_set {
      type    = "Microsoft_BotManagerRuleSet"
      version = "1.0"
    }` : ''}
  }
  custom_rules {
    name                 = "RateLimitPorIP"
    priority             = 1
    rule_type            = "RateLimitRule"
    rate_limit_duration  = "FiveMins"
    rate_limit_threshold = ${Number(p.rateLimit) || 2000}
    group_rate_limit_by  = "ClientAddr"
    action               = "Block"
    match_conditions {
      match_variables {
        variable_name = "RemoteAddr"
      }
      operator           = "IPMatch"
      negation_condition = true
      match_values       = ["255.255.255.255/32"]
    }
  }
}
`);
        }
        for (const { t } of others) block(`# TODO: ${t.data.label} no admite WAF directo en Azure; pon Front Door o Application Gateway delante.\n`);
        break;
      }
      case 'az-ddos':
        break; // plan creado con la red
      case 'az-appgw': {
        const waf = ins(n).find(({ s }) => sid(s) === 'az-waf')?.s;
        const backends = outs(n).map(({ t }) => t);
        const paas = backends.filter((t) => ['az-appservice', 'az-containerapps', 'az-functions', 'az-apim'].includes(sid(t)));
        const fqdn = (t: ServiceNode) =>
          ({
            'az-appservice': `azurerm_linux_web_app.${tfName(t)}.default_hostname`,
            'az-functions': `azurerm_linux_function_app.${tfName(t)}.default_hostname`,
            'az-containerapps': `azurerm_container_app.${tfName(t)}.ingress[0].fqdn`,
            'az-apim': `replace(azurerm_api_management.${tfName(t)}.gateway_url, "https://", "")`,
          })[sid(t)]!;
        appgwPools.set(n.id, `[for p in azurerm_application_gateway.${name}.backend_address_pool : p.id]`);
        block(`
${header}
resource "azurerm_public_ip" "${name}" {
  name                = "pip-${name.replace(/_/g, '-')}"
  ${RG}
  ${LOC}
  allocation_method   = "Static"
  sku                 = "Standard"
  zones               = ["1", "2", "3"]
}

resource "azurerm_application_gateway" "${name}" {
  name                = "agw-\${local.name}"
  ${RG}
  ${LOC}
  zones               = ["1", "2", "3"]${waf ? `
  firewall_policy_id  = azurerm_web_application_firewall_policy.${tfName(waf)}.id` : ''}

  sku {
    name = ${q(waf ? 'WAF_v2' : 'Standard_v2')}
    tier = ${q(waf ? 'WAF_v2' : 'Standard_v2')}
  }
  autoscale_configuration {
    min_capacity = 2
    max_capacity = 10
  }
  gateway_ip_configuration {
    name      = "gw-ip"
    subnet_id = ${subnet ?? 'null # TODO: subnet dedicada para el Application Gateway'}
  }
  frontend_port {
    name = "http"
    port = 80
  }
  frontend_ip_configuration {
    name                 = "public"
    public_ip_address_id = azurerm_public_ip.${name}.id
  }
  backend_address_pool {
    name${paas.length ? `  = "app"
    fqdns = [${paas.map(fqdn).join(', ')}]` : ' = "app"'}
  }
  backend_http_settings {
    name                  = "app"
    cookie_based_affinity = "Disabled"
    port                  = ${paas.length ? 443 : backends[0] ? targetOf(n, backends[0]).port : 8080}
    protocol              = ${q(paas.length ? 'Https' : 'Http')}
    request_timeout       = 30${paas.length ? `
    pick_host_name_from_backend_address = true` : ''}
  }
  http_listener {
    name                           = "http"
    frontend_ip_configuration_name = "public"
    frontend_port_name             = "http"
    protocol                       = "Http" # TODO: listener HTTPS con certificado de Key Vault
  }
  request_routing_rule {
    name                       = "app"
    priority                   = 100
    rule_type                  = "Basic"
    http_listener_name         = "http"
    backend_address_pool_name  = "app"
    backend_http_settings_name = "app"
  }
}
`);
        break;
      }
      case 'az-lb':
        appgwPools.set(n.id, `[azurerm_lb_backend_address_pool.${name}.id]`);
        block(`
${header}
resource "azurerm_lb" "${name}" {
  name                = "lb-\${local.name}-${name.replace(/_/g, '-')}"
  ${RG}
  ${LOC}
  sku                 = "Standard"
  frontend_ip_configuration {
    name                          = "internal"
    subnet_id                     = ${subnet ?? 'null # TODO'}
    private_ip_address_allocation = "Dynamic"
    zones                         = ["1", "2", "3"]
  }
}

resource "azurerm_lb_backend_address_pool" "${name}" {
  name            = "app"
  loadbalancer_id = azurerm_lb.${name}.id
}
`);
        break;
      case 'az-apim': {
        const tier = String(p.type ?? 'Standard v2');
        const sku = { Consumption: 'Consumption_0', 'Basic v2': 'BasicV2_1', 'Standard v2': 'StandardV2_1', 'Premium v2': 'Premium_1' }[tier] ?? 'StandardV2_1';
        const jwt = outs(n).some(({ t }) => sid(t) === 'az-entra');
        block(`
${header}
resource "azurerm_api_management" "${name}" {
  name                = "apim-\${local.name}-\${random_string.suffix.result}"
  ${RG}
  ${LOC}
  publisher_name      = var.project
  publisher_email     = "plataforma@ejemplo.com" # TODO
  sku_name            = ${q(sku)}
  identity {
    type = "SystemAssigned"
  }
}
${jwt ? `# TODO: política <validate-jwt> (o validate-azure-ad-token) con el emisor de Entra External ID en las APIs.\n` : ''}# TODO: APIs/operaciones y backends (Functions, App Service, Container Apps).
`);
        break;
      }
      case 'az-natgw':
        block(`
${header}
resource "azurerm_public_ip" "${name}" {
  name                = "pip-nat-\${local.name}"
  ${RG}
  ${LOC}
  allocation_method   = "Static"
  sku                 = "Standard"
}

resource "azurerm_nat_gateway" "${name}" {
  name                = "nat-\${local.name}"
  ${RG}
  ${LOC}
  sku_name            = "Standard"
}

resource "azurerm_nat_gateway_public_ip_association" "${name}" {
  nat_gateway_id       = azurerm_nat_gateway.${name}.id
  public_ip_address_id = azurerm_public_ip.${name}.id
}
${hasSubnet('subnet-private') ? `
resource "azurerm_subnet_nat_gateway_association" "${name}" {
  subnet_id      = azurerm_subnet.private.id
  nat_gateway_id = azurerm_nat_gateway.${name}.id
}
` : ''}`);
        break;
      case 'az-pe':
        block(`
${header}
# TODO: azurerm_private_endpoint hacia el recurso PaaS (${p.service}) con su zona DNS privada:
#   subnet_id = ${subnet ?? 'azurerm_subnet.private.id'}
#   private_service_connection { private_connection_resource_id = <id del recurso>  subresource_names = [${q(p.service)}] }
`);
        break;
      case 'az-vpngw':
        block(`\n${header}\n# TODO: VPN Gateway requiere una "GatewaySubnet" dedicada y tarda ~30‑45 min en aprovisionarse.\n`);
        break;
      case 'az-vmss': {
        const lb = ins(n).find(({ s }) => ['az-appgw', 'az-lb'].includes(sid(s)))?.s;
        const count = Math.max(1, Number(p.count) || 2);
        block(`
${header}
resource "azurerm_linux_virtual_machine_scale_set" "${name}" {
  name                = "vmss-${name.replace(/_/g, '-')}"
  ${RG}
  ${LOC}
  sku                 = ${q(p.instanceType || 'Standard_D2s_v5')}
  instances           = ${count}
  zones               = ["1", "2", "3"]
  admin_username      = "azureuser"
  upgrade_mode        = "Manual" # TODO: "Rolling" con health probe para despliegues sin corte
  admin_ssh_key {
    username   = "azureuser"
    public_key = var.ssh_public_key
  }
  source_image_reference {
    publisher = "Canonical"
    offer     = "ubuntu-24_04-lts"
    sku       = "server"
    version   = "latest"
  }
  os_disk {
    storage_account_type = "Premium_LRS"
    caching              = "ReadWrite"
  }
  network_interface {
    name    = "nic"
    primary = true
    ip_configuration {
      name      = "internal"
      primary   = true
      subnet_id = ${subnet ?? 'null # TODO'}${lb ? `
      ${sid(lb) === 'az-appgw' ? 'application_gateway_backend_address_pool_ids' : 'load_balancer_backend_address_pool_ids'} = ${appgwPools.get(lb.id) ?? (sid(lb) === 'az-appgw' ? `[for p in azurerm_application_gateway.${tfName(lb)}.backend_address_pool : p.id]` : `[azurerm_lb_backend_address_pool.${tfName(lb)}.id]`)}` : ''}
    }
  }
  identity {
    type = "SystemAssigned"
  }
}
${p.autoscaling ? `
resource "azurerm_monitor_autoscale_setting" "${name}" {
  name                = "autoscale-${name.replace(/_/g, '-')}"
  ${RG}
  ${LOC}
  target_resource_id  = azurerm_linux_virtual_machine_scale_set.${name}.id
  profile {
    name = "default"
    capacity {
      default = ${count}
      minimum = ${p.minSize !== undefined ? Math.min(count, Number(p.minSize)) : count}
      maximum = ${p.maxSize !== undefined ? Math.max(count, Number(p.maxSize)) : count * 3}
    }
    rule {
      metric_trigger {
        metric_name        = "Percentage CPU"
        metric_resource_id = azurerm_linux_virtual_machine_scale_set.${name}.id
        time_grain         = "PT1M"
        statistic          = "Average"
        time_window        = "PT5M"
        time_aggregation   = "Average"
        operator           = "GreaterThan"
        threshold          = ${Number(p.targetCpu) || 70}
      }
      scale_action {
        direction = "Increase"
        type      = "ChangeCount"
        value     = "1"
        cooldown  = "PT5M"
      }
    }
  }
}
` : ''}`);
        break;
      }
      case 'az-functions': {
        const rt = String(p.runtime ?? 'node 20');
        const stack = rt.startsWith('python') ? 'python_version = "3.11"' : rt.startsWith('dotnet') ? 'dotnet_version              = "8.0"\n      use_dotnet_isolated_runtime = true' : rt.startsWith('java') ? 'java_version = "17"' : 'node_version = "20"';
        const envs = outs(n)
          .filter(({ t }) => ['az-cosmos', 'az-blob', 'az-servicebus', 'az-keyvault', 'az-openai', 'az-eventgrid'].includes(sid(t)))
          .map(({ t }) => {
            const tn = tfName(t);
            const ref = { 'az-cosmos': `azurerm_cosmosdb_account.${tn}.endpoint`, 'az-blob': `azurerm_storage_account.${tn}.primary_blob_endpoint`, 'az-servicebus': `"\${azurerm_servicebus_namespace.main.name}.servicebus.windows.net"`, 'az-keyvault': `azurerm_key_vault.${tn}.vault_uri`, 'az-openai': `azurerm_cognitive_account.${tn}.endpoint`, 'az-eventgrid': `azurerm_eventgrid_topic.${tn}.endpoint` }[sid(t)];
            return `    ${tn.toUpperCase()} = ${ref}`;
          });
        block(`
${header}
resource "azurerm_storage_account" "${name}_fn" {
  name                     = ${globalName(n, 22).replace('${', 'fn${')}
  ${RG}
  ${LOC}
  account_tier             = "Standard"
  account_replication_type = "ZRS"
  min_tls_version          = "TLS1_2"
}

resource "azurerm_service_plan" "${name}" {
  name                = "asp-${name.replace(/_/g, '-')}"
  ${RG}
  ${LOC}
  os_type             = "Linux"
  sku_name            = "Y1" # TODO: Flex Consumption (FC1) para VNet integration y escalado más rápido
}

resource "azurerm_linux_function_app" "${name}" {
  name                       = "func-\${local.name}-${name.replace(/_/g, '-').slice(0, 20)}"
  ${RG}
  ${LOC}
  service_plan_id            = azurerm_service_plan.${name}.id
  storage_account_name       = azurerm_storage_account.${name}_fn.name
  storage_account_access_key = azurerm_storage_account.${name}_fn.primary_access_key
  https_only                 = true
  site_config {
    application_stack {
      ${stack}
    }${outs(n).some(({ t }) => sid(t) === 'az-appinsights') ? `
    application_insights_connection_string = azurerm_application_insights.${tfName(outs(n).find(({ t }) => sid(t) === 'az-appinsights')!.t)}.connection_string` : ''}
  }
  identity {
    type = "SystemAssigned"
  }${envs.length ? `
  app_settings = {
${envs.join('\n')}
  }` : ''}
}
`);
        break;
      }
      case 'az-appservice': {
        const instances = Math.max(1, Number(p.instances) || 2);
        const sku = String(p.sku ?? 'P1v3');
        block(`
${header}
resource "azurerm_service_plan" "${name}" {
  name                   = "asp-${name.replace(/_/g, '-')}"
  ${RG}
  ${LOC}
  os_type                = "Linux"
  sku_name               = ${q(sku)}
  worker_count           = ${instances}${sku.startsWith('P') && instances >= 2 ? `
  zone_balancing_enabled = true` : ''}
}

resource "azurerm_linux_web_app" "${name}" {
  name                      = "app-\${local.name}-${name.replace(/_/g, '-').slice(0, 20)}"
  ${RG}
  ${LOC}
  service_plan_id           = azurerm_service_plan.${name}.id
  https_only                = true${hasSubnet('subnet-private') ? `
  virtual_network_subnet_id = azurerm_subnet.private.id # TODO: subnet delegada a Microsoft.Web/serverFarms` : ''}
  site_config {
    always_on           = true
    minimum_tls_version = "1.2"
    application_stack {
      node_version = "20-lts"
    }
  }
  identity {
    type = "SystemAssigned"
  }
}
`);
        break;
      }
      case 'az-containerapps': {
        const cpu = Math.max(0.25, Math.round(((Number(p.cpu) || 512) / 1024) * 4) / 4);
        const desired = Math.max(0, Number(p.desired) || 2);
        const acr = ins(n).find(({ s }) => sid(s) === 'az-acr')?.s;
        block(`
${header}
resource "azurerm_container_app" "${name}" {
  name                         = ${q(`ca-${name.replace(/_/g, '-')}`.slice(0, 32))}
  container_app_environment_id = azurerm_container_app_environment.main.id
  ${RG}
  revision_mode                = "Single"
  identity {
    type = "SystemAssigned"
  }${acr ? `
  registry {
    server   = azurerm_container_registry.${tfName(acr)}.login_server
    identity = "System"
  }` : ''}
  template {
    min_replicas = ${desired}
    max_replicas = ${Math.max(desired * 5, 10)}
    container {
      name   = ${q(name.replace(/_/g, '-').slice(0, 30))}
      image  = ${q(p.image || 'mcr.microsoft.com/k8se/quickstart:latest')} # TODO: imagen de tu registro
      cpu    = ${cpu}
      memory = "${cpu * 2}Gi"
    }
    http_scale_rule {
      name                = "http"
      concurrent_requests = "50"
    }
  }
  ingress {
    external_enabled = ${ins(n).some(({ s }) => ['az-appgw', 'az-frontdoor', 'az-apim'].includes(sid(s)))}
    target_port      = ${listenPort(n)}
    traffic_weight {
      percentage      = 100
      latest_revision = true
    }
  }
}
`);
        break;
      }
      case 'az-aks': {
        const nodesN = Math.max(1, Number(p.nodes) || 3);
        block(`
${header}
resource "azurerm_kubernetes_cluster" "${name}" {
  name                      = "aks-\${local.name}"
  ${RG}
  ${LOC}
  dns_prefix                = "\${local.name}"
  kubernetes_version        = ${q(p.version || '1.30')}
  oidc_issuer_enabled       = true
  workload_identity_enabled = true
  azure_policy_enabled      = true
  default_node_pool {
    name                 = "system"
    vm_size              = "Standard_D4s_v5"
    auto_scaling_enabled = true
    min_count            = ${nodesN}
    max_count            = ${nodesN * 3}
    zones                = ["1", "2", "3"]${subnet ? `
    vnet_subnet_id       = ${subnet}` : ''}
  }
  identity {
    type = "SystemAssigned"
  }
  network_profile {
    network_plugin = "azure"
    network_policy = "azure"
  }
}
`);
        break;
      }
      case 'az-acr':
        block(`
${header}
resource "azurerm_container_registry" "${name}" {
  name                = ${globalName(n, 50)}
  ${RG}
  ${LOC}
  sku                 = "Premium"
  admin_enabled       = false
}
`);
        break;
      case 'az-blob':
        block(`
${header}
resource "azurerm_storage_account" "${name}" {
  name                            = ${globalName(n, 24)}
  ${RG}
  ${LOC}
  account_tier                    = "Standard"
  account_replication_type        = "ZRS"
  min_tls_version                 = "TLS1_2"
  https_traffic_only_enabled      = true
  allow_nested_items_to_be_public = ${!!p.public}
  shared_access_key_enabled       = false # solo Entra ID
  blob_properties {
    versioning_enabled = ${p.versioning !== false}
    delete_retention_policy {
      days = 7
    }
  }
}

resource "azurerm_storage_container" "${name}" {
  name                  = "data"
  storage_account_id    = azurerm_storage_account.${name}.id
  container_access_type = ${q(p.public ? 'blob' : 'private')}
}
`);
        break;
      case 'az-files':
        block(`
${header}
resource "azurerm_storage_account" "${name}" {
  name                     = ${globalName(n, 24)}
  ${RG}
  ${LOC}
  account_tier             = "Premium"
  account_kind             = "FileStorage"
  account_replication_type = "ZRS"
  min_tls_version          = "TLS1_2"
}

resource "azurerm_storage_share" "${name}" {
  name               = "share"
  storage_account_id = azurerm_storage_account.${name}.id
  quota              = 100
}
`);
        break;
      case 'az-sql':
        block(`
${header}
resource "azurerm_mssql_server" "${name}" {
  name                          = ${globalName(n, 60, true)}
  ${RG}
  ${LOC}
  version                       = "12.0"
  minimum_tls_version           = "1.2"
  public_network_access_enabled = false # acceso por Private Endpoint
  azuread_administrator {
    login_username              = "sql-admins"
    object_id                   = data.azurerm_client_config.current.object_id # TODO: grupo de administradores
    azuread_authentication_only = true
  }
}

resource "azurerm_mssql_database" "${name}" {
  name           = ${q(name.replace(/_/g, '-'))}
  server_id      = azurerm_mssql_server.${name}.id
  sku_name       = ${q(p.instanceClass || 'GP_Gen5_2')}
  zone_redundant = ${!!p.multiAZ}
  max_size_gb    = ${Number(p.storage) || 50}
  short_term_retention_policy {
    retention_days = 7
  }
}
`);
        break;
      case 'az-postgres': {
        if (p.engine === 'mysql') {
          block(`\n${header}\n# TODO: azurerm_mysql_flexible_server con subnet delegada (Microsoft.DBforMySQL/flexibleServers) y zona DNS privada.\n`);
          break;
        }
        const sizes = [32768, 65536, 131072, 262144, 524288, 1048576];
        const want = (Number(p.storage) || 64) * 1024;
        const storage = sizes.find((x) => x >= want) ?? 1048576;
        block(`
${header}
resource "azurerm_postgresql_flexible_server" "${name}" {
  name                          = ${globalName(n, 60, true)}
  ${RG}
  ${LOC}
  version                       = "16"
  sku_name                      = ${q(p.instanceClass || 'GP_Standard_D2s_v3')}
  storage_mb                    = ${storage}
  zone                          = "1"
  backup_retention_days         = 7${vnet ? `
  delegated_subnet_id           = azurerm_subnet.pg.id
  private_dns_zone_id           = azurerm_private_dns_zone.pg.id` : ''}
  public_network_access_enabled = false${p.multiAZ ? `
  high_availability {
    mode                      = "ZoneRedundant"
    standby_availability_zone = "2"
  }` : ''}
  authentication {
    active_directory_auth_enabled = true
    password_auth_enabled         = false
    tenant_id                     = data.azurerm_client_config.current.tenant_id
  }${vnet ? `
  depends_on = [azurerm_private_dns_zone_virtual_network_link.pg]` : ''}
}
`);
        break;
      }
      case 'az-cosmos': {
        const mode = String(p.billing ?? 'Autoscale');
        block(`
${header}
resource "azurerm_cosmosdb_account" "${name}" {
  name                          = ${globalName(n, 44, true)}
  ${RG}
  ${LOC}
  offer_type                    = "Standard"
  kind                          = "GlobalDocumentDB"
  local_authentication_disabled = true # solo Entra ID
  consistency_policy {
    consistency_level = "Session"
  }
  geo_location {
    location          = azurerm_resource_group.main.location
    failover_priority = 0
    zone_redundant    = true
  }${mode === 'Serverless' ? `
  capabilities {
    name = "EnableServerless"
  }` : ''}
  backup {${p.pitr !== false ? `
    type = "Continuous"
    tier = "Continuous7Days"` : `
    type                = "Periodic"
    interval_in_minutes = 240
    retention_in_hours  = 8
    storage_redundancy  = "Geo"`}
  }
}

resource "azurerm_cosmosdb_sql_database" "${name}" {
  name                = "app"
  ${RG}
  account_name        = azurerm_cosmosdb_account.${name}.name
}

resource "azurerm_cosmosdb_sql_container" "${name}" {
  name                  = ${q(name.replace(/_/g, '-'))}
  ${RG}
  account_name          = azurerm_cosmosdb_account.${name}.name
  database_name         = azurerm_cosmosdb_sql_database.${name}.name
  partition_key_paths   = [${q(String(p.pk || '/pk').startsWith('/') ? p.pk || '/pk' : `/${p.pk}`)}]
  partition_key_version = 2${mode === 'Autoscale' ? `
  autoscale_settings {
    max_throughput = ${Math.max(1000, Number(p.ru) || 4000)}
  }` : mode === 'Provisioned' ? `
  throughput            = ${Math.max(400, Number(p.ru) || 400)}` : ''}
}
`);
        break;
      }
      case 'az-redis': {
        const [tier, size] = String(p.nodeType ?? 'Standard C1').split(' ');
        const family = size?.[0] ?? 'C';
        const capacity = Number(size?.slice(1)) || 1;
        const premium = tier === 'Premium';
        const replicas = Number(p.replicas) || 0;
        block(`
${header}
resource "azurerm_redis_cache" "${name}" {
  name                 = ${globalName(n, 63, true)}
  ${RG}
  ${LOC}
  capacity             = ${capacity}
  family               = ${q(family)}
  sku_name             = ${q(tier || 'Standard')}
  non_ssl_port_enabled = false
  minimum_tls_version  = "1.2"${premium && replicas > 0 ? `
  replicas_per_primary = ${replicas}
  zones                = ["1", "2"]` : ''}
  redis_configuration {}
}
`);
        break;
      }
      case 'az-search':
        block(`
${header}
resource "azurerm_search_service" "${name}" {
  name                          = ${globalName(n, 60, true)}
  ${RG}
  ${LOC}
  sku                           = "standard"
  replica_count                 = ${Math.max(1, Number(p.instances) || 2)}
  partition_count               = 1
  local_authentication_enabled  = false
  public_network_access_enabled = false
}
`);
        break;
      case 'az-synapse':
        block(`\n${header}\n# TODO: azurerm_synapse_workspace requiere un Data Lake (storage con HNS) y un filesystem.\n`);
        break;
      case 'az-servicebus':
        block(`
${header}
resource "azurerm_servicebus_queue" "${name}" {
  name                                 = ${q(name.replace(/_/g, '-'))}
  namespace_id                         = azurerm_servicebus_namespace.main.id
  requires_session                     = ${!!p.fifo}
  dead_lettering_on_message_expiration = ${p.dlq !== false}
  max_delivery_count                   = 10
  lock_duration                        = "PT${Math.min(300, Math.max(5, Number(p.visibility) || 60))}S"
}
`);
        break;
      case 'az-servicebus-topic': {
        const subs = outs(n).filter(({ t }) => sid(t) === 'az-servicebus');
        block(`
${header}
resource "azurerm_servicebus_topic" "${name}" {
  name         = ${q(name.replace(/_/g, '-'))}
  namespace_id = azurerm_servicebus_namespace.main.id
}
${subs
  .map(
    ({ t }) => `
resource "azurerm_servicebus_subscription" "${name}_${tfName(t)}" {
  name               = ${q(tfName(t).replace(/_/g, '-'))}
  topic_id           = azurerm_servicebus_topic.${name}.id
  max_delivery_count = 10
  forward_to         = azurerm_servicebus_queue.${tfName(t)}.name
}
`,
  )
  .join('')}`);
        break;
      }
      case 'az-eventgrid': {
        const targets = outs(n).filter(({ t }) => ['az-servicebus', 'az-servicebus-topic', 'az-eventhubs', 'az-functions'].includes(sid(t)));
        block(`
${header}
resource "azurerm_eventgrid_topic" "${name}" {
  name                = "evgt-\${local.name}-${name.replace(/_/g, '-').slice(0, 20)}"
  ${RG}
  ${LOC}
  input_schema        = "CloudEventSchemaV1_0"
  local_auth_enabled  = false
}
${targets
  .map(({ t }) => {
    const tn = tfName(t);
    const ep =
      sid(t) === 'az-servicebus'
        ? `service_bus_queue_endpoint_id = azurerm_servicebus_queue.${tn}.id`
        : sid(t) === 'az-servicebus-topic'
          ? `service_bus_topic_endpoint_id = azurerm_servicebus_topic.${tn}.id`
          : sid(t) === 'az-eventhubs'
            ? `eventhub_endpoint_id = azurerm_eventhub.${tn}.id`
            : `azure_function_endpoint {
    function_id = "\${azurerm_linux_function_app.${tn}.id}/functions/TODO" # TODO: nombre de la función
  }`;
    return `
resource "azurerm_eventgrid_event_subscription" "${name}_${tn}" {
  name                  = ${q(`to-${tn.replace(/_/g, '-')}`.slice(0, 64))}
  scope                 = azurerm_eventgrid_topic.${name}.id
  event_delivery_schema = "CloudEventSchemaV1_0"
  ${ep}
}
`;
  })
  .join('')}`);
        break;
      }
      case 'az-eventhubs':
        block(`
${header}
resource "azurerm_eventhub" "${name}" {
  name              = ${q(name.replace(/_/g, '-'))}
  namespace_id      = azurerm_eventhub_namespace.main.id
  partition_count   = 4
  message_retention = 1
}
`);
        break;
      case 'az-logicapps':
        block(`
${header}
resource "azurerm_logic_app_workflow" "${name}" {
  name                = "logic-${name.replace(/_/g, '-')}"
  ${RG}
  ${LOC}
  identity {
    type = "SystemAssigned"
  }
}
# TODO: definición del flujo (o Durable Functions si prefieres código)
`);
        break;
      case 'az-entra':
        block(`
${header}
# Entra External ID se configura en un tenant externo, fuera de esta suscripción.
# TODO: registra la aplicación con el provider "azuread" (azuread_application) y
#       define los flujos de usuario y las políticas de acceso condicional (MFA: ${p.mfa}).
`);
        break;
      case 'az-keyvault':
        block(`
${header}
resource "azurerm_key_vault" "${name}" {
  name                          = ${globalName(n, 24, true)}
  ${RG}
  ${LOC}
  tenant_id                     = data.azurerm_client_config.current.tenant_id
  sku_name                      = "standard"
  enable_rbac_authorization     = true
  purge_protection_enabled      = true
  soft_delete_retention_days    = 90
  public_network_access_enabled = false # acceso por Private Endpoint
  network_acls {
    default_action = "Deny"
    bypass         = "AzureServices"
  }
}
`);
        break;
      case 'az-keyvault-keys':
        block(`
${header}
resource "azurerm_key_vault" "${name}" {
  name                       = ${globalName(n, 24, true)}
  ${RG}
  ${LOC}
  tenant_id                  = data.azurerm_client_config.current.tenant_id
  sku_name                   = "premium"
  enable_rbac_authorization  = true
  purge_protection_enabled   = true
  soft_delete_retention_days = 90
}

resource "azurerm_role_assignment" "${name}_officer" {
  scope                = azurerm_key_vault.${name}.id
  role_definition_name = "Key Vault Crypto Officer"
  principal_id         = data.azurerm_client_config.current.object_id
}

resource "azurerm_key_vault_key" "${name}" {
  name         = "cmk"
  key_vault_id = azurerm_key_vault.${name}.id
  key_type     = "RSA-HSM"
  key_size     = 3072
  key_opts     = ["wrapKey", "unwrapKey"]
  rotation_policy {
    expire_after         = "P1Y"
    notify_before_expiry = "P29D"
    automatic {
      time_before_expiry = "P30D"
    }
  }
  depends_on = [azurerm_role_assignment.${name}_officer]
}
`);
        break;
      case 'az-cert':
        block(`\n${header}\n# TODO: certificado en Key Vault (azurerm_key_vault_certificate) referenciado por Front Door / Application Gateway.\n`);
        break;
      case 'az-defender':
        block(`
${header}
resource "azurerm_security_center_subscription_pricing" "${name}" {
  for_each      = toset(["VirtualMachines", "SqlServers", "StorageAccounts", "Containers", "KeyVaults", "Arm", "CloudPosture"])
  tier          = "Standard"
  resource_type = each.value
}
`);
        break;
      case 'az-sentinel':
        block(`
${header}
resource "azurerm_sentinel_log_analytics_workspace_onboarding" "${name}" {
  workspace_id = azurerm_log_analytics_workspace.main.id
}
`);
        break;
      case 'az-monitor':
        block(`
${header}
resource "azurerm_monitor_action_group" "${name}" {
  name                = "ag-\${local.name}"
  ${RG}
  short_name          = ${q(alnum(slug, 12) || 'alertas')}
  email_receiver {
    name          = "plataforma"
    email_address = "plataforma@ejemplo.com" # TODO
  }
}
`);
        break;
      case 'az-appinsights':
        block(`
${header}
resource "azurerm_application_insights" "${name}" {
  name                = "appi-\${local.name}"
  ${RG}
  ${LOC}
  workspace_id        = azurerm_log_analytics_workspace.main.id
  application_type    = "web"
}
`);
        break;
      case 'az-activitylog':
        block(`
${header}
resource "azurerm_monitor_diagnostic_setting" "${name}" {
  name                       = "activity-log"
  target_resource_id         = "/subscriptions/\${data.azurerm_client_config.current.subscription_id}"
  log_analytics_workspace_id = azurerm_log_analytics_workspace.main.id
  enabled_log {
    category = "Administrative"
  }
  enabled_log {
    category = "Security"
  }
  enabled_log {
    category = "Policy"
  }
}
`);
        break;
      case 'az-datafactory':
        block(`
${header}
resource "azurerm_data_factory" "${name}" {
  name                = ${globalName(n, 63, true)}
  ${RG}
  ${LOC}
  identity {
    type = "SystemAssigned"
  }
}
`);
        break;
      case 'az-databricks':
        block(`
${header}
resource "azurerm_databricks_workspace" "${name}" {
  name                = "dbw-\${local.name}"
  ${RG}
  ${LOC}
  sku                 = "premium"
}
`);
        break;
      case 'az-openai':
        block(`
${header}
resource "azurerm_cognitive_account" "${name}" {
  name                          = ${globalName(n, 60, true)}
  ${RG}
  ${LOC}
  kind                          = "OpenAI"
  sku_name                      = "S0"
  custom_subdomain_name         = ${globalName(n, 60, true)}
  local_auth_enabled            = false
  public_network_access_enabled = false
}

resource "azurerm_cognitive_deployment" "${name}" {
  name                 = ${q(p.model || 'gpt-4o')}
  cognitive_account_id = azurerm_cognitive_account.${name}.id
  model {
    format  = "OpenAI"
    name    = ${q(p.model || 'gpt-4o')}
    version = "2024-08-06" # TODO: versión disponible en tu región
  }
  sku {
    name     = "Standard"
    capacity = 10 # miles de tokens por minuto
  }
}
# ${p.guardrails === false ? 'TODO: activa' : 'Revisa'} los filtros de contenido y Prompt Shields del deployment (política RAI).
`);
        break;
      case 'az-ml':
      case 'az-fabric':
      case 'az-devops':
        block(`\n${header}\n# TODO: ${getService(sid(n)).name} — sin plantilla automática todavía.\n`);
        break;
      default:
        break;
    }
  }

  if (roleBlocks.length || cosmosRoles.length || dbNotes.length) {
    out.push('# ═════════════ RBAC de mínimo privilegio (derivado de las flechas del diagrama)\n');
    out.push(...roleBlocks.map((b) => b.trim() + '\n'), ...cosmosRoles.map((b) => b.trim() + '\n'));
    if (dbNotes.length) out.push(dbNotes.join('\n') + '\n');
  }

  // ───────── Salidas
  const outputs: string[] = [];
  for (const n of services) {
    const name = tfName(n);
    if (sid(n) === 'az-frontdoor') outputs.push(`output "${name}_host" {\n  value = azurerm_cdn_frontdoor_endpoint.${name}.host_name\n}`);
    if (sid(n) === 'az-appgw') outputs.push(`output "${name}_ip" {\n  value = azurerm_public_ip.${name}.ip_address\n}`);
    if (sid(n) === 'az-apim') outputs.push(`output "${name}_url" {\n  value = azurerm_api_management.${name}.gateway_url\n}`);
    if (sid(n) === 'az-functions') outputs.push(`output "${name}_host" {\n  value = azurerm_linux_function_app.${name}.default_hostname\n}`);
  }
  if (outputs.length) block('# ═════════════ Salidas\n' + outputs.join('\n\n'));
  return out.join('\n');
}
