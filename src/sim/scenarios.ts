export type ScenarioKind = 'load' | 'spike' | 'instance-failure' | 'az-failure' | 'node-outage' | 'region-failure' | 'slow-dependency' | 'data-corruption' | 'ransomware' | 'gameday' | 'ddos-l7' | 'ddos-l34' | 'web-attacks';

export interface Scenario {
  kind: ScenarioKind;
  /** Duración total simulada (s). */
  duration: number;
  /** Tráfico legítimo base (req/s). */
  baseRps: number;
  /** Pico (prueba de carga / pico de tráfico) en req/s. */
  peakRps: number;
  /** Momento del evento (s). */
  eventAt: number;
  /** Duración del evento (s). */
  eventDuration: number;
  /** Pieza objetivo (falla, DDoS, ataques). Vacío = automático. */
  targetId: string;
  /** DDoS L7 */
  attackRps: number;
  botIps: number;
  cacheablePct: number;
  /** DDoS L3/L4 */
  gbps: number;
  /** Ataques web (req/s por tipo) */
  sqliRps: number;
  xssRps: number;
  lfiRps: number;
  botsRps: number;
  /** Dependencia lenta: latencia extra (ms). */
  extraLatency: number;
  /** Corrupción de datos: minutos hasta que alguien lo nota. */
  detectMin: number;
}

export type ScenarioGroup = 'carga' | 'fallas' | 'datos' | 'caos' | 'ataques';
export const SCENARIO_GROUPS: { id: ScenarioGroup; label: string }[] = [
  { id: 'carga', label: 'Carga' },
  { id: 'fallas', label: 'Fallas y failover' },
  { id: 'datos', label: 'Datos' },
  { id: 'caos', label: 'Caos' },
  { id: 'ataques', label: 'Ataques' },
];

export interface ScenarioMeta {
  kind: ScenarioKind;
  group: ScenarioGroup;
  label: string;
  short: string;
  description: string;
  fields: (keyof Scenario)[];
  target?: 'compute-or-data' | 'any' | 'entry' | 'data';
  defaults: Partial<Scenario>;
}

export const SCENARIOS: ScenarioMeta[] = [
  {
    kind: 'load',
    group: 'carga',
    label: 'Prueba de carga',
    short: 'Carga',
    description: 'Sube el tráfico de forma gradual hasta el pico para encontrar el primer cuello de botella.',
    fields: ['baseRps', 'peakRps', 'duration'],
    defaults: { baseRps: 50, peakRps: 3000, duration: 600, eventAt: 0 },
  },
  {
    kind: 'spike',
    group: 'carga',
    label: 'Pico súbito de tráfico',
    short: 'Pico',
    description: 'Tráfico normal y de repente un pico (campaña, Black Friday). Muestra si el autoescalado reacciona a tiempo.',
    fields: ['baseRps', 'peakRps', 'eventAt', 'eventDuration', 'duration'],
    defaults: { baseRps: 200, peakRps: 2000, eventAt: 60, eventDuration: 240, duration: 600 },
  },
  {
    kind: 'instance-failure',
    group: 'fallas',
    label: 'Falla de una instancia',
    short: 'Instancia',
    description: 'Se cae una instancia de la pieza elegida (EC2, contenedor, BD primaria, nodo de caché…). Muestra el failover.',
    fields: ['targetId', 'baseRps', 'eventAt', 'duration'],
    target: 'compute-or-data',
    defaults: { baseRps: 300, eventAt: 60, duration: 600 },
  },
  {
    kind: 'az-failure',
    group: 'fallas',
    label: 'Caída de una zona de disponibilidad',
    short: 'Zona (AZ)',
    description: 'Se pierde una AZ completa: la mitad de las instancias, las piezas sin Multi‑AZ y sus primarios.',
    fields: ['baseRps', 'eventAt', 'duration'],
    defaults: { baseRps: 300, eventAt: 60, duration: 600 },
  },
  {
    kind: 'node-outage',
    group: 'fallas',
    label: 'Falla de una dependencia',
    short: 'Dependencia',
    description: 'Una pieza deja de responder por completo (API externa, Cognito, una cola…). Muestra el radio de impacto.',
    fields: ['targetId', 'baseRps', 'eventAt', 'eventDuration', 'duration'],
    target: 'any',
    defaults: { baseRps: 300, eventAt: 60, eventDuration: 180, duration: 480 },
  },
  {
    kind: 'region-failure',
    group: 'fallas',
    label: 'Caída de la región completa',
    short: 'Región',
    description: 'Se pierde toda la región principal. Pone a prueba la estrategia de DR: región secundaria, réplicas de datos entre regiones y el cambio de DNS (Route 53).',
    fields: ['baseRps', 'eventAt', 'duration'],
    defaults: { baseRps: 300, eventAt: 120, duration: 3600 },
  },
  {
    kind: 'slow-dependency',
    group: 'fallas',
    label: 'Dependencia lenta (tormenta de reintentos)',
    short: 'Lentitud',
    description: 'Una dependencia no se cae: se pone lenta. Los hilos se quedan esperando, los reintentos multiplican la carga y la falla se propaga. Pone a prueba los timeouts, reintentos y circuit breakers.',
    fields: ['targetId', 'baseRps', 'extraLatency', 'eventAt', 'eventDuration', 'duration'],
    target: 'any',
    defaults: { baseRps: 300, extraLatency: 5000, eventAt: 60, eventDuration: 240, duration: 480 },
  },
  {
    kind: 'data-corruption',
    group: 'datos',
    label: 'Corrupción o borrado de datos',
    short: 'Corrupción',
    description: 'Un bug o un error humano (DROP, UPDATE sin WHERE, borrado masivo) daña los datos. Multi‑AZ y las réplicas copian el daño: solo sirven los backups, PITR y el versionado.',
    fields: ['targetId', 'baseRps', 'detectMin', 'eventAt', 'duration'],
    target: 'data',
    defaults: { baseRps: 300, detectMin: 10, eventAt: 120, duration: 7200 },
  },
  {
    kind: 'ransomware',
    group: 'datos',
    label: 'Ransomware en la cuenta',
    short: 'Ransomware',
    description: 'Un atacante con credenciales cifra o borra los datos y también intenta borrar los backups. Solo sobrevive lo que está en otra cuenta con bloqueo inmutable.',
    fields: ['targetId', 'baseRps', 'eventAt', 'duration'],
    target: 'data',
    defaults: { baseRps: 300, eventAt: 120, duration: 7200 },
  },
  {
    kind: 'gameday',
    group: 'caos',
    label: 'Game Day: pico + caída de AZ + dependencia lenta',
    short: 'Game Day',
    description: 'Prueba combinada: empieza un pico de tráfico, en pleno pico cae una zona de disponibilidad y después una dependencia se pone lenta. Así fallan los sistemas reales: varias cosas a la vez.',
    fields: ['baseRps', 'peakRps', 'extraLatency', 'eventAt', 'duration'],
    defaults: { baseRps: 200, peakRps: 1500, extraLatency: 3000, eventAt: 60, eventDuration: 600, duration: 900 },
  },
  {
    kind: 'ddos-l7',
    group: 'ataques',
    label: 'DDoS de aplicación (HTTP flood)',
    short: 'DDoS L7',
    description: 'Una botnet inunda el punto de entrada con requests HTTP. Evalúa WAF (rate limit, Bot Control), CDN y Shield.',
    fields: ['targetId', 'baseRps', 'attackRps', 'botIps', 'cacheablePct', 'eventAt', 'eventDuration', 'duration'],
    target: 'entry',
    defaults: { baseRps: 300, attackRps: 50000, botIps: 2000, cacheablePct: 0, eventAt: 60, eventDuration: 300, duration: 480 },
  },
  {
    kind: 'ddos-l34',
    group: 'ataques',
    label: 'DDoS volumétrico (L3/L4)',
    short: 'DDoS L3/L4',
    description: 'Inundación de red (SYN/UDP flood, reflexión). Evalúa si el punto de entrada está protegido por Shield.',
    fields: ['targetId', 'baseRps', 'gbps', 'eventAt', 'eventDuration', 'duration'],
    target: 'entry',
    defaults: { baseRps: 300, gbps: 200, eventAt: 60, eventDuration: 240, duration: 420 },
  },
  {
    kind: 'web-attacks',
    group: 'ataques',
    label: 'Ataques web (OWASP)',
    short: 'Ataques web',
    description: 'Inyección SQL, XSS, path traversal y bots maliciosos mezclados con tráfico legítimo. Evalúa las reglas del WAF.',
    fields: ['targetId', 'baseRps', 'sqliRps', 'xssRps', 'lfiRps', 'botsRps', 'botIps', 'eventAt', 'eventDuration', 'duration'],
    target: 'entry',
    defaults: { baseRps: 300, sqliRps: 40, xssRps: 40, lfiRps: 20, botsRps: 400, botIps: 50, eventAt: 30, eventDuration: 300, duration: 420 },
  },
];

export const SCENARIO_MAP = Object.fromEntries(SCENARIOS.map((s) => [s.kind, s])) as Record<ScenarioKind, ScenarioMeta>;

export const FIELD_LABEL: Record<keyof Scenario, { label: string; unit?: string; min?: number; max?: number; step?: number }> = {
  kind: { label: 'Escenario' },
  duration: { label: 'Duración', unit: 's', min: 60, max: 14400, step: 60 },
  baseRps: { label: 'Tráfico normal', unit: 'req/s', min: 0, step: 50 },
  peakRps: { label: 'Tráfico pico', unit: 'req/s', min: 1, step: 100 },
  eventAt: { label: 'Inicio del evento', unit: 's', min: 0, step: 10 },
  eventDuration: { label: 'Duración del evento', unit: 's', min: 10, step: 10 },
  targetId: { label: 'Pieza objetivo' },
  attackRps: { label: 'Requests del ataque', unit: 'req/s', min: 0, step: 1000 },
  botIps: { label: 'IPs atacantes', unit: 'IPs', min: 1, step: 100 },
  cacheablePct: { label: 'Ataque a URLs cacheables', unit: '%', min: 0, max: 100, step: 10 },
  gbps: { label: 'Volumen del ataque', unit: 'Gbps', min: 1, step: 10 },
  sqliRps: { label: 'Inyección SQL', unit: 'req/s', min: 0, step: 10 },
  xssRps: { label: 'XSS', unit: 'req/s', min: 0, step: 10 },
  lfiRps: { label: 'Path traversal / LFI', unit: 'req/s', min: 0, step: 10 },
  botsRps: { label: 'Bots / scrapers', unit: 'req/s', min: 0, step: 50 },
  extraLatency: { label: 'Latencia extra', unit: 'ms', min: 100, max: 120000, step: 500 },
  detectMin: { label: 'Se detecta a los', unit: 'min', min: 0, max: 1440, step: 5 },
};

export function defaultScenario(kind: ScenarioKind = 'spike'): Scenario {
  const base: Scenario = {
    kind,
    duration: 600,
    baseRps: 200,
    peakRps: 2000,
    eventAt: 60,
    eventDuration: 240,
    targetId: '',
    attackRps: 50000,
    botIps: 2000,
    cacheablePct: 0,
    gbps: 200,
    sqliRps: 40,
    xssRps: 40,
    lfiRps: 20,
    botsRps: 400,
    extraLatency: 5000,
    detectMin: 10,
  };
  return { ...base, ...SCENARIO_MAP[kind].defaults, kind };
}
