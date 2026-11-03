/**
 * Seguridad del proyecto: prácticas y guardrails que no son una pieza del diagrama pero que
 * sí se configuran (y varias generan Terraform). Los controles del modelo de amenazas los leen
 * en lugar de pedir que el arquitecto marque casillas sueltas en cada amenaza.
 */

export type SecurityGroupKey = 'cuenta' | 'operacion' | 'pipeline' | 'aplicacion' | 'datos' | 'ia';

export interface SecuritySetting {
  key: string;
  group: SecurityGroupKey;
  label: string;
  help: string;
  /** Qué genera en el Terraform exportado (si genera algo). */
  terraform?: string;
}

export const SECURITY_GROUPS: { id: SecurityGroupKey; label: string; help: string }[] = [
  { id: 'cuenta', label: 'Cuenta y gobierno', help: 'Guardrails de la cuenta y de la organización.' },
  { id: 'operacion', label: 'Operación y respuesta', help: 'Detectar, alertar y recuperarse.' },
  { id: 'pipeline', label: 'Pipeline (CI/CD)', help: 'Controles antes de llegar a producción.' },
  { id: 'aplicacion', label: 'Aplicación', help: 'Lo que hace el código.' },
  { id: 'datos', label: 'Datos', help: 'Bases de datos, cachés y auditoría de acceso.' },
  { id: 'ia', label: 'IA / LLM', help: 'Solo aplica si usas modelos de lenguaje.' },
];

export const SECURITY_SETTINGS: SecuritySetting[] = [
  // Cuenta y gobierno
  { key: 'scp', group: 'cuenta', label: 'Guardrails de la organización (SCP)', help: 'Impiden en toda la cuenta apagar CloudTrail/GuardDuty, usar regiones no aprobadas o salir de la organización.', terraform: 'aws_organizations_policy (SCP) lista para adjuntar' },
  { key: 'boundary', group: 'cuenta', label: 'Permission boundary en los roles de las aplicaciones', help: 'Pone un techo a lo que puede hacer cualquier rol de la app, aunque su política tenga comodines.', terraform: 'aws_iam_policy de límite + permissions_boundary en cada rol' },
  { key: 'rootMfa', group: 'cuenta', label: 'MFA en root y acceso humano por SSO (IAM Identity Center)', help: 'Nadie entra con usuarios IAM de larga duración; root solo con MFA y guardado bajo llave.' },
  { key: 'logLock', group: 'cuenta', label: 'Logs de auditoría inmutables (Object Lock)', help: 'Un atacante con acceso no puede borrar el rastro de CloudTrail.', terraform: 'Bucket de CloudTrail con Object Lock en modo compliance' },
  { key: 'offsiteBackup', group: 'cuenta', label: 'Copias en otra cuenta o región (AWS Backup con vault lock)', help: 'Protege contra borrado malicioso y ransomware.', terraform: 'aws_backup_vault con lock + plan diario' },
  // Operación
  { key: 'siem', group: 'operacion', label: 'Hallazgos de seguridad enviados al equipo (EventBridge → SNS / SIEM)', help: 'Los hallazgos de GuardDuty llegan a alguien que los atiende.', terraform: 'Regla de EventBridge para GuardDuty → tema SNS de alertas' },
  { key: 'ddosRunbook', group: 'operacion', label: 'Alarmas de tráfico anómalo y runbook de DDoS', help: 'Saber que te están atacando y qué hacer.', terraform: 'Alarma de CloudWatch por picos de peticiones/5xx en el balanceador' },
  { key: 'patching', group: 'operacion', label: 'Parcheo automático (SSM Patch Manager) y Amazon Inspector', help: 'Servidores y contenedores sin vulnerabilidades conocidas.', terraform: 'aws_inspector2_enabler + asociación AWS-RunPatchBaseline' },
  { key: 'restoreTests', group: 'operacion', label: 'Restauraciones de backup probadas periódicamente', help: 'Un backup que nunca se restauró no es un backup.' },
  // Pipeline
  { key: 'sast', group: 'pipeline', label: 'SAST y DAST en el pipeline', help: 'Análisis estático del código y pruebas dinámicas contra un ambiente de staging.' },
  { key: 'sca', group: 'pipeline', label: 'Escaneo de dependencias (SCA) y actualización continua', help: 'Dependabot, Renovate, Snyk, Trivy…' },
  { key: 'secretScan', group: 'pipeline', label: 'Escaneo de secretos en el repositorio', help: 'Pre-commit y CI (gitleaks, GitHub secret scanning).' },
  // Aplicación
  { key: 'inputValidation', group: 'aplicacion', label: 'Validación de entradas, consultas parametrizadas y output encoding', help: 'La defensa real contra inyecciones y XSS; el WAF es una capa extra.' },
  { key: 'objectAuthz', group: 'aplicacion', label: 'Autorización por objeto (BOLA)', help: 'Cada consulta verifica que el recurso pertenece al usuario.' },
  { key: 'sessions', group: 'aplicacion', label: 'Sesiones cortas, cookies Secure/HttpOnly y revocación de tokens', help: 'Limita el daño de una sesión robada.' },
  { key: 'businessAudit', group: 'aplicacion', label: 'Auditoría de negocio (quién, qué, cuándo, desde dónde)', help: 'Registro de acciones sensibles con retención definida.' },
  { key: 'webhookSig', group: 'aplicacion', label: 'Verificación de firma en webhooks y llamadas de terceros', help: 'HMAC, mTLS o token del emisor en cada llamada.' },
  { key: 'antiReplay', group: 'aplicacion', label: 'Protección contra repeticiones (timestamp + nonce / idempotencia)', help: 'Una petición capturada no se puede reenviar.' },
  { key: 'schemaValidation', group: 'aplicacion', label: 'Validación del esquema de los mensajes en los consumidores', help: 'Un mensaje malformado no tumba ni engaña al consumidor.' },
  { key: 'resourcePolicies', group: 'aplicacion', label: 'Políticas de recurso en colas y tópicos (solo productores autorizados)', help: 'Nadie más puede publicar mensajes falsos.' },
  { key: 'dataMin', group: 'aplicacion', label: 'Minimización de datos hacia terceros', help: 'Solo se envía lo necesario; sin datos personales de más.' },
  { key: 'resilience', group: 'aplicacion', label: 'Timeouts, reintentos con backoff y circuit breaker', help: 'Una dependencia lenta no arrastra a toda la aplicación.' },
  { key: 'serviceAuth', group: 'aplicacion', label: 'Autenticación entre servicios internos (mTLS / tokens)', help: 'Un servicio comprometido no puede llamar a cualquier otro.' },
  { key: 'logHygiene', group: 'aplicacion', label: 'Logs sin datos sensibles ni tokens', help: 'Enmascarado de PII y secretos antes de escribir logs.' },
  { key: 'captcha', group: 'aplicacion', label: 'CAPTCHA o challenge en login, registro y recuperación', help: 'Frena relleno de credenciales y creación masiva de cuentas.' },
  // Datos
  { key: 'dbTls', group: 'datos', label: 'TLS obligatorio en las conexiones a bases de datos', help: 'La base de datos rechaza conexiones sin cifrar.', terraform: 'Parameter group con rds.force_ssl / require_secure_transport' },
  { key: 'cacheAuth', group: 'datos', label: 'AUTH token o RBAC de usuarios en las cachés', help: 'Acceder a la red no basta para leer la caché.' },
  { key: 'dataAuditLogs', group: 'datos', label: 'Logs de acceso a los datos (data events, audit logs del motor)', help: 'Saber quién leyó o cambió datos sensibles.', terraform: 'Exportación de logs de auditoría de RDS/Aurora a CloudWatch' },
  // IA
  { key: 'llmIO', group: 'ia', label: 'Separar instrucciones de datos y validar la salida del modelo', help: 'Mitiga la inyección de prompts.' },
  { key: 'llmAgency', group: 'ia', label: 'Mínimo privilegio en las herramientas que el modelo puede invocar', help: 'El modelo no puede hacer más daño que un usuario normal.' },
  { key: 'llmPii', group: 'ia', label: 'No enviar secretos ni datos personales al modelo', help: 'Filtrado previo de PII y credenciales.' },
];

export const SETTING_MAP = new Map(SECURITY_SETTINGS.map((s) => [s.key, s]));

/** Controles manuales del modelo de amenazas → ajuste del proyecto que los cumple. */
export const CONTROL_SETTING: Record<string, string[]> = {
  agency: ['llmAgency'],
  alarms: ['ddosRunbook'],
  alerts: ['siem'],
  audit: ['businessAudit'],
  auth: ['cacheAuth'],
  authn: ['serviceAuth'],
  bola: ['objectAuthz'],
  boundary: ['boundary', 'scp'],
  captcha: ['captcha'],
  code: ['inputValidation'],
  datalogs: ['dataAuditLogs'],
  immutable: ['logLock'],
  minimize: ['dataMin'],
  nosecrets: ['logHygiene'],
  offsite: ['offsiteBackup'],
  pii: ['llmPii'],
  policy: ['resourcePolicies'],
  replay: ['antiReplay'],
  resilience: ['resilience'],
  restore: ['restoreTests'],
  'root-mfa': ['rootMfa'],
  sast: ['sast'],
  scan: ['secretScan'],
  schema: ['schemaValidation'],
  separate: ['llmIO'],
  session: ['sessions'],
  sig: ['webhookSig'],
  tls: ['dbTls'],
};

export type SecurityConfig = Record<string, boolean>;
