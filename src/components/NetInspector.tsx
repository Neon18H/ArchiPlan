import { useMemo, useState } from 'react';
import { create } from 'zustand';
import { getService, primaryCloud } from '../catalog/catalog';
import { byId, isService, placementOf, uid } from '../lib/graph';
import { useCloudText } from '../lib/useCloud';
import {
  defaultPort,
  effectiveNet,
  inVpc,
  isAnyCidr,
  isLb,
  listenersOf,
  listenPort,
  needsSg,
  originProtocol,
  PORT_NAME,
  PORT_PRESETS,
  portLabel,
  ruleSentence,
  semantics,
  sgColor,
  targetOf,
  type AccessSource,
} from '../net/model';
import { analyzeNetwork, type EdgeVerdict, type NetAnalysis } from '../net/reach';
import { useStore } from '../store';
import type { AppEdge, AppNode, Listener, NetFix, SecurityGroup, ServiceNode, SgRule, SgSource } from '../types';
import { Modal } from './Modals';

/* ───────────────────────── estado de la UI de red */

type NetTab = 'access' | 'groups';
interface NetUi {
  /** Vista de red sobre el lienzo. */
  view: boolean;
  tab: NetTab;
  sgId: string | null;
  setView: (v: boolean) => void;
  open: (tab?: NetTab, sgId?: string | null) => void;
  setTab: (t: NetTab) => void;
  setSg: (id: string | null) => void;
}
export const useNetUi = create<NetUi>((set) => ({
  view: false,
  tab: 'access',
  sgId: null,
  setView: (v) => set({ view: v }),
  open: (tab = 'access', sgId = null) => {
    set({ tab, sgId });
    window.dispatchEvent(new CustomEvent('archiplan:open', { detail: 'net' }));
  },
  setTab: (t) => set({ tab: t }),
  setSg: (id) => set({ sgId: id }),
}));

/** Análisis de red memorizado para la UI. */
export function useNetAnalysis(): NetAnalysis {
  const nodes = useStore((s) => s.nodes);
  const edges = useStore((s) => s.edges);
  const groups = useStore((s) => s.securityGroups);
  return useMemo(() => analyzeNetwork(nodes, edges, groups), [nodes, edges, groups]);
}

const label = (n: AppNode | undefined) => (n?.data as { label?: string } | undefined)?.label ?? '?';
const sgWord = (nodes: AppNode[]) => (primaryCloud(nodes) === 'azure' ? 'NSG' : 'Security Group');
const cdnWord = (nodes: AppNode[]) => (primaryCloud(nodes) === 'azure' ? 'Front Door' : 'CloudFront');

export function Switch({ on, onChange, label: aria, disabled }: { on: boolean; onChange: (v: boolean) => void; label: string; disabled?: boolean }) {
  return (
    <button type="button" role="switch" aria-checked={on} aria-label={aria} disabled={disabled} className={`switch ${on ? 'on' : ''}`} onClick={() => onChange(!on)}>
      <span />
    </button>
  );
}

function FixButton({ fix }: { fix: NetFix }) {
  return (
    <button className="btn small fix" onClick={() => useStore.getState().applyNetFix(fix)}>
      ⚡ {fix.label}
    </button>
  );
}

/** Estado de una flecha en palabras, para listas y tarjetas. */
function verdictLine(v: EdgeVerdict) {
  const err = v.checks.find((c) => !c.ok && c.severity === 'error');
  const warn = v.checks.find((c) => !c.ok && c.severity === 'warn');
  return { err, warn, text: err ? err.title : warn ? warn.title : v.kind === 'egress' ? 'Puede salir (HTTPS)' : `Permitido en ${portLabel(v.port)}` };
}

/** ¿El fallo depende de reglas de SG (y por lo tanto el interruptor lo arregla)? */
const sgOnly = (v: EdgeVerdict) => v.checks.filter((c) => !c.ok && c.severity === 'error').every((c) => c.id.startsWith('sg-'));

/* ───────────────────────── modo de red (automática / personalizada) */

function ModeLine() {
  const nodes = useStore((s) => s.nodes);
  const manual = useStore((s) => s.securityGroups.length > 0);
  const { resetSecurityGroups } = useStore.getState();
  return (
    <div className={`net-modeline ${manual ? 'manual' : ''}`}>
      {manual ? (
        <>
          <span>
            <b>Red personalizada</b> · mandan tus reglas
          </span>
          <button className="linklike small" onClick={() => window.confirm(`Se descartarán tus ${sgWord(nodes)}s y la red se volverá a calcular a partir de las flechas. ¿Continuar?`) && resetSecurityGroups()}>
            Volver a automática
          </button>
        </>
      ) : (
        <span>
          <b>Red automática</b> · se calcula sola a partir de las flechas. Si cambias algo, pasa a personalizada.
        </span>
      )}
    </div>
  );
}

/* ───────────────────────── tarjeta de red de una flecha */

export function EdgeNetSection({ edge, prominent }: { edge: AppEdge; prominent?: boolean }) {
  const a = useNetAnalysis();
  const nodes = useStore((s) => s.nodes);
  const ct = useCloudText();
  const [why, setWhy] = useState(false);
  const v = a.verdicts.get(edge.id);
  if (!v || v.kind === 'none') return null;
  const map = byId(nodes);
  const from = map.get(v.fromId);
  const to = map.get(v.toId);
  if (v.kind === 'managed')
    return (
      <div className="net-card muted-card">
        <div className="net-card-title">Red</div>
        <p className="small muted">La nube invoca esta conexión por su cuenta (evento o servicio administrado): no pasa por {sgWord(nodes)}s ni puertos.</p>
      </div>
    );
  const { err, warn } = verdictLine(v);
  const allowedBySg = !v.checks.some((c) => !c.ok && c.id.startsWith('sg-'));
  const otherErr = v.checks.filter((c) => !c.ok && c.severity === 'error' && !c.id.startsWith('sg-'));
  return (
    <div className={`net-card ${prominent ? 'prominent' : ''} ${err ? 'bad' : 'good'}`}>
      <div className="net-card-title">Tráfico de red</div>
      <div className="net-flow">
        <b>{label(from)}</b>
        <span className="net-flow-arrow">
          → <em>{v.kind === 'egress' ? 'salida HTTPS' : portLabel(v.port)}</em> →
        </span>
        <b>{label(to)}</b>
      </div>
      <div className="net-toggle-row">
        <Switch on={allowedBySg} onChange={(on) => useStore.getState().setAccess(edge.id, on)} label="Permitir este tráfico" />
        <div>
          <b>{allowedBySg ? 'Permitido por los grupos de seguridad' : 'Bloqueado por los grupos de seguridad'}</b>
          <div className="small muted">{allowedBySg ? 'Apágalo para bloquearlo (quita la regla que lo deja pasar).' : 'Enciéndelo para crear la regla que hace falta.'}</div>
        </div>
      </div>
      {otherErr.length > 0 && (
        <div className="net-other">
          {otherErr.map((c) => (
            <div key={c.id} className="net-problem">
              <b>✗ {ct(c.title)}</b>
              <span>{ct(c.detail)}</span>
              {c.fix && <FixButton fix={c.fix} />}
            </div>
          ))}
        </div>
      )}
      {!err && warn && (
        <div className="net-problem warn">
          <b>! {ct(warn.title)}</b>
          <span>{ct(warn.detail)}</span>
          {warn.fix && <FixButton fix={warn.fix} />}
        </div>
      )}
      <div className={`net-verdict-line ${err ? 'bad' : 'good'}`}>{err ? `La petición fallaría: ${v.failure ?? 'bloqueada'}` : '✓ Una petición pasaría por aquí sin problemas'}</div>
      {v.checks.length > 0 && (
        <>
          <button className="linklike small" onClick={() => setWhy(!why)}>
            {why ? '▾' : '▸'} Qué se revisó ({v.checks.length})
          </button>
          {why && (
            <ul className="net-checks">
              {v.checks.map((c) => (
                <li key={c.id} className={c.ok ? 'ok' : c.severity}>
                  <span>{c.ok ? '✓' : c.severity === 'error' ? '✗' : '!'}</span>
                  <div>
                    {ct(c.title)}
                    {!c.ok && c.detail && <div className="muted small">{ct(c.detail)}</div>}
                  </div>
                </li>
              ))}
            </ul>
          )}
        </>
      )}
    </div>
  );
}

/* ───────────────────────── tarjeta de red de una pieza */

const COMMON_PORTS = [80, 443, 3000, 8080];

function PortPicker({ node }: { node: ServiceNode }) {
  const { setNet } = useStore.getState();
  const cur = listenPort(node);
  const def = defaultPort(node);
  const chips = [...new Set([def, ...COMMON_PORTS])].slice(0, 5);
  return (
    <div className="net-block">
      <div className="net-block-title">Escucha en</div>
      <div className="port-row">
        <input className="port-input" type="number" min={1} max={65535} value={cur} onChange={(e) => setNet(node.id, { port: Math.max(1, Math.min(65535, Number(e.target.value) || def)) === def ? undefined : Math.max(1, Math.min(65535, Number(e.target.value) || def)) }, 'port')} aria-label="Puerto de escucha" />
        <span className="port-name">{PORT_NAME[cur] ?? 'puerto personalizado'}</span>
      </div>
      <div className="chips">
        {chips.map((p) => (
          <button key={p} className={`port-chip ${p === cur ? 'on' : ''}`} onClick={() => setNet(node.id, { port: p === def ? undefined : p })}>
            {p}
            {p === def ? ' · por defecto' : ''}
          </button>
        ))}
      </div>
    </div>
  );
}

function AllowForm({ node, sources }: { node: ServiceNode; sources: ServiceNode[] }) {
  const nodes = useStore((s) => s.nodes);
  const [src, setSrc] = useState('');
  const [cidr, setCidr] = useState('10.0.0.0/16');
  const [port, setPort] = useState(listenPort(node));
  const [open, setOpen] = useState(false);
  if (!open)
    return (
      <button className="btn small add-allow" onClick={() => (setOpen(true), setPort(listenPort(node)))}>
        + Permitir acceso
      </button>
    );
  const parsed: AccessSource | null = src.startsWith('node:') ? { kind: 'node', id: src.slice(5) } : src === 'internet' ? { kind: 'internet' } : src === 'cdn' ? { kind: 'cdn' } : src === 'cidr' && /^\d+\.\d+\.\d+\.\d+\/\d+$/.test(cidr.trim()) ? { kind: 'cidr', value: cidr.trim() } : null;
  return (
    <div className="allow-form">
      <div className="allow-sentence">
        <span>Permitir</span>
        <select value={port} onChange={(e) => setPort(Number(e.target.value))} aria-label="Puerto">
          {[...new Set([listenPort(node), ...isLb(node) ? listenersOf(node).map((l) => l.port) : [], 443, 80, 22])].map((p) => (
            <option key={p} value={p}>
              {portLabel(p)}
            </option>
          ))}
        </select>
        <span>desde</span>
        <select value={src} onChange={(e) => setSrc(e.target.value)} aria-label="Origen">
          <option value="">elige…</option>
          <optgroup label="Piezas del diagrama">
            {sources.map((n) => (
              <option key={n.id} value={`node:${n.id}`}>
                {n.data.label}
              </option>
            ))}
          </optgroup>
          <optgroup label="Otros orígenes">
            <option value="cdn">{cdnWord(nodes)} (sus IPs)</option>
            <option value="internet">Cualquier IP de Internet</option>
            <option value="cidr">Un rango de IPs…</option>
          </optgroup>
        </select>
        {src === 'cidr' && <input value={cidr} onChange={(e) => setCidr(e.target.value)} className={/^\d+\.\d+\.\d+\.\d+\/\d+$/.test(cidr.trim()) ? '' : 'invalid'} aria-label="Rango CIDR" />}
      </div>
      {src === 'internet' && ['datastore', 'cache', 'search'].includes(getService(node.data.serviceId).role) && <div className="small warn-text">⚠ Abrir una base de datos a Internet es un riesgo grave.</div>}
      <div className="row gap">
        <button className="btn small primary" disabled={!parsed} onClick={() => (useStore.getState().allowInto(node.id, parsed!, port), setOpen(false), setSrc(''))}>
          Permitir
        </button>
        <button className="btn small" onClick={() => setOpen(false)}>
          Cancelar
        </button>
      </div>
    </div>
  );
}

export function NetSection({ node }: { node: ServiceNode }) {
  const nodes = useStore((s) => s.nodes);
  const edges = useStore((s) => s.edges);
  const groups = useStore((s) => s.securityGroups);
  const { setNet, ensureManualNet, removeRule } = useStore.getState();
  const a = useNetAnalysis();
  const ct = useCloudText();
  const [adv, setAdv] = useState(false);
  const map = byId(nodes);
  const def = getService(node.data.serviceId);
  const SG = sgWord(nodes);
  const cdn = def.role === 'cdn';
  const vpc = inVpc(node, map);
  const lb = isLb(node);
  const sgable = needsSg(node, map);
  const mine = edges
    .filter((e) => e.source === node.id || e.target === node.id)
    .map((e) => ({ e, v: a.verdicts.get(e.id) }))
    .filter((x): x is { e: AppEdge; v: EdgeVerdict } => !!x.v && (x.v.kind === 'connect' || x.v.kind === 'egress'));
  if (!vpc && !cdn && !mine.length) return null;
  const net = node.data.net ?? {};
  const eff = effectiveNet(nodes, edges, groups);
  const assigned = eff.sgIdsOf(node).map((id) => eff.groups.find((g) => g.id === id)).filter((g): g is SecurityGroup => !!g);
  const listens = !lb && !cdn && vpc && def.role !== 'netgw';
  const publicSubnet = placementOf(node, map) === 'subnet-public' && def.role === 'compute';
  const sources = nodes.filter((n): n is ServiceNode => isService(n) && n.id !== node.id && !['observability', 'kms', 'cert', 'devops', 'analytics', 'waf', 'netgw', 'dns'].includes(getService(n.data.serviceId).role));
  const inbound = assigned.flatMap((g) => g.inbound.map((r) => ({ g, r })));
  const outbound = assigned.flatMap((g) => g.outbound.map((r) => ({ g, r })));
  const blocked = mine.filter(({ v }) => !v.ok).length;

  return (
    <div className="insp-section net-section">
      <div className="insp-section-title row between">
        <span>Red</span>
        {blocked > 0 ? <span className="net-badge bad">{blocked} bloqueada{blocked > 1 ? 's' : ''}</span> : mine.length > 0 ? <span className="net-badge good">todo conecta</span> : null}
      </div>

      {listens && <PortPicker node={node} />}

      {publicSubnet && (
        <label className="toggle">
          <input type="checkbox" checked={!!net.publicIp} onChange={(e) => setNet(node.id, { publicIp: e.target.checked })} />
          <span>IP pública (acceso directo desde Internet)</span>
        </label>
      )}

      {cdn && (
        <div className="net-block">
          <div className="net-block-title">Cómo llama a su origen</div>
          <div className="seg-choice">
            {(
              [
                ['https-only', 'Solo HTTPS'],
                ['http-only', 'Solo HTTP'],
                ['match-viewer', 'Igual que el usuario'],
              ] as const
            ).map(([k, l]) => (
              <button key={k} className={originProtocol(node) === k ? 'on' : ''} onClick={() => setNet(node.id, { originProtocol: k })}>
                {l}
              </button>
            ))}
          </div>
        </div>
      )}

      {lb && <LbEditor node={node} />}

      {sgable && (
        <div className="net-block">
          <div className="net-block-title">Quién puede entrar</div>
          {inbound.length === 0 && <div className="empty-note">Nadie: {SG === 'NSG' ? 'el NSG' : 'el grupo'} no tiene reglas de entrada.</div>}
          <ul className="access-list">
            {inbound.map(({ g, r }) => (
              <li key={g.id + r.id}>
                <span className="dot" style={{ background: sgColor(eff.groups, g.id) }} title={g.name} />
                <span className={`access-text ${r.peer.kind === 'cidr' && isAnyCidr(r.peer.value) ? 'open' : ''}`}>{ruleSentence(r, 'inbound', nodes, eff.groups, eff.sgIdsOf, cdnWord(nodes))}</span>
                <button className="x" title="Quitar este acceso" aria-label="Quitar este acceso" onClick={() => removeRule(g.id, 'inbound', r.id)}>
                  ×
                </button>
              </li>
            ))}
          </ul>
          <AllowForm node={node} sources={sources} />
        </div>
      )}

      {mine.length > 0 && (
        <div className="net-block">
          <div className="net-block-title">Sus conexiones</div>
          {mine.map(({ e, v }) => {
            const other = map.get(e.source === node.id ? e.target : e.source);
            const { err, warn } = verdictLine(v);
            const fix = (err ?? warn)?.fix;
            return (
              <div key={e.id} className={`conn-status ${err ? 'bad' : warn ? 'warn' : 'good'}`}>
                <button className="linklike conn-status-main" onClick={() => useStore.getState().focus([e.id, e.source, e.target])}>
                  <span className="cs-ico">{err ? '✗' : warn ? '!' : '✓'}</span>
                  <span className="cs-name">
                    {e.source === node.id ? '→' : '←'} {label(other)}
                  </span>
                  <span className="cs-port">{v.kind === 'egress' ? 'HTTPS' : v.port}</span>
                </button>
                {err && <span className="cs-why">{ct(err.title)}</span>}
                {fix && <FixButton fix={fix} />}
              </div>
            );
          })}
        </div>
      )}

      {sgable && (
        <>
          <button className="linklike small" onClick={() => setAdv(!adv)}>
            {adv ? '▾' : '▸'} Avanzado: {SG}s, salidas
          </button>
          {adv && (
            <div className="net-adv">
              <div className="chips">
                {assigned.map((g) => (
                  <span key={g.id} className="sg-chip" style={{ ['--sg' as string]: sgColor(eff.groups, g.id) }}>
                    <button className="linklike" onClick={() => useNetUi.getState().open('groups', g.id)}>
                      {g.name}
                    </button>
                    <button className="x" aria-label={`Quitar ${g.name}`} onClick={() => (ensureManualNet(), setNet(node.id, { sgIds: (useStore.getState().nodes.find((n) => n.id === node.id) as ServiceNode).data.net?.sgIds?.filter((x) => x !== g.id) ?? [] }))}>
                      ×
                    </button>
                  </span>
                ))}
                {!assigned.length && <span className="muted small">Sin {SG}: se aplicaría el grupo por defecto.</span>}
              </div>
              <select
                value=""
                onChange={(e) => {
                  const v = e.target.value;
                  if (!v) return;
                  ensureManualNet();
                  if (v === '__new') useStore.getState().applyNetFix({ kind: 'create-sg', nodeId: node.id, label: `${SG} nuevo` });
                  else {
                    const cur = (useStore.getState().nodes.find((n) => n.id === node.id) as ServiceNode).data.net?.sgIds ?? [];
                    setNet(node.id, { sgIds: [...cur, v] });
                  }
                }}
              >
                <option value="">+ Asignar otro {SG}…</option>
                {eff.groups
                  .filter((g) => !assigned.includes(g))
                  .map((g) => (
                    <option key={g.id} value={g.id}>
                      {g.name}
                    </option>
                  ))}
                <option value="__new">Crear uno nuevo para esta pieza</option>
              </select>
              <div className="net-block-title">Puede salir hacia</div>
              <ul className="access-list">
                {outbound.map(({ g, r }) => (
                  <li key={g.id + r.id}>
                    <span className="dot" style={{ background: sgColor(eff.groups, g.id) }} title={g.name} />
                    <span className="access-text">{ruleSentence(r, 'outbound', nodes, eff.groups, eff.sgIdsOf, cdnWord(nodes))}</span>
                    <button className="x" aria-label="Quitar" onClick={() => removeRule(g.id, 'outbound', r.id)}>
                      ×
                    </button>
                  </li>
                ))}
                {!outbound.length && <li className="empty-note">No puede salir a ningún lado.</li>}
              </ul>
            </div>
          )}
        </>
      )}
    </div>
  );
}

/* ───────────────────────── balanceador: listeners y target groups */

function LbEditor({ node }: { node: ServiceNode }) {
  const nodes = useStore((s) => s.nodes);
  const edges = useStore((s) => s.edges);
  const { setNet } = useStore.getState();
  const map = byId(nodes);
  const ls = listenersOf(node);
  const nlb = node.data.serviceId === 'nlb';
  const setLs = (next: Listener[]) => setNet(node.id, { listeners: next }, 'listeners');
  const targets = edges.map((e) => (e.source === node.id ? map.get(e.target) : undefined)).filter((n): n is ServiceNode => isService(n) && ['compute', 'workflow'].includes(getService(n.data.serviceId).role));
  return (
    <>
      <div className="net-block">
        <div className="net-block-title">Recibe en (listeners)</div>
        {ls.map((l) => {
          const tls = l.protocol === 'HTTPS' || l.protocol === 'TLS';
          return (
            <div key={l.id} className="listener-card">
              <div className="listener-line">
                <select value={l.protocol} onChange={(e) => setLs(ls.map((x) => (x.id === l.id ? { ...x, protocol: e.target.value as Listener['protocol'], cert: ['HTTPS', 'TLS'].includes(e.target.value) ? true : x.cert } : x)))} aria-label="Protocolo">
                  {(nlb ? ['TCP', 'TLS'] : ['HTTPS', 'HTTP']).map((p) => (
                    <option key={p}>{p}</option>
                  ))}
                </select>
                <input type="number" min={1} max={65535} value={l.port} onChange={(e) => setLs(ls.map((x) => (x.id === l.id ? { ...x, port: Number(e.target.value) } : x)))} aria-label="Puerto" />
                <span className="muted">→</span>
                <select value={l.action} onChange={(e) => setLs(ls.map((x) => (x.id === l.id ? { ...x, action: e.target.value as Listener['action'] } : x)))} aria-label="Acción">
                  <option value="forward">envía a los servidores</option>
                  {!nlb && <option value="redirect-https">redirige a HTTPS</option>}
                </select>
                <button className="x" aria-label="Quitar listener" onClick={() => setLs(ls.filter((x) => x.id !== l.id))}>
                  ×
                </button>
              </div>
              {tls && (
                <label className={`cert-line ${l.cert ? 'ok' : 'bad'}`}>
                  <input type="checkbox" checked={!!l.cert} onChange={(e) => setLs(ls.map((x) => (x.id === l.id ? { ...x, cert: e.target.checked } : x)))} />
                  {l.cert ? 'Con certificado TLS' : 'Sin certificado: HTTPS no funcionará'}
                </label>
              )}
            </div>
          );
        })}
        <button className="btn small" onClick={() => setLs([...ls, { id: uid('l'), port: ls.some((x) => x.port === 443) ? 8443 : 443, protocol: nlb ? 'TCP' : 'HTTPS', action: 'forward', cert: !nlb }])}>
          + Listener
        </button>
      </div>
      {targets.length > 0 && (
        <div className="net-block">
          <div className="net-block-title">Envía a (target groups)</div>
          {targets.map((t) => {
            const tg = targetOf(node, t);
            const set = (p: Partial<typeof tg>) => setNet(node.id, { targets: { ...(node.data.net?.targets ?? {}), [t.id]: { ...tg, ...p } } }, `tg:${t.id}`);
            const lp = listenPort(t);
            const mismatch = tg.port !== lp;
            return (
              <div key={t.id} className={`listener-card ${mismatch ? 'bad' : ''}`}>
                <div className="tg-title">{t.data.label}</div>
                <div className="listener-line">
                  <select value={tg.protocol} onChange={(e) => set({ protocol: e.target.value as typeof tg.protocol })} aria-label="Protocolo del target">
                    {(nlb ? ['TCP'] : ['HTTP', 'HTTPS']).map((p) => (
                      <option key={p}>{p}</option>
                    ))}
                  </select>
                  <input type="number" min={1} max={65535} value={tg.port} onChange={(e) => set({ port: Number(e.target.value) })} aria-label="Puerto del target" />
                  {!nlb && (
                    <>
                      <span className="muted small">salud</span>
                      <input className="hp" value={tg.healthPath} onChange={(e) => set({ healthPath: e.target.value })} placeholder="/health" aria-label="Ruta de health check" />
                    </>
                  )}
                </div>
                {mismatch && (
                  <div className="tg-warn">
                    {t.data.label} escucha en {lp}, no en {tg.port}: los health checks fallan (503).{' '}
                    <button className="linklike" onClick={() => set({ port: lp })}>
                      Usar {lp}
                    </button>
                  </div>
                )}
              </div>
            );
          })}
        </div>
      )}
    </>
  );
}

/* ───────────────────────── leyenda de la vista de red (sobre el lienzo) */

export function NetLegend() {
  const a = useNetAnalysis();
  const setView = useNetUi((s) => s.setView);
  const open = useNetUi((s) => s.open);
  const vs = [...a.verdicts.values()].filter((v) => v.kind === 'connect' || v.kind === 'egress');
  const bad = vs.filter((v) => !v.ok).length;
  return (
    <div className="net-legend">
      <div className="row between">
        <b>Vista de red</b>
        <button className="x" onClick={() => setView(false)} aria-label="Cerrar vista de red">
          ×
        </button>
      </div>
      <ModeLine />
      <div className="net-legend-stats">
        <span className="ok">✓ {vs.length - bad} conectan</span>
        <span className={bad ? 'bad' : 'muted'}>⛔ {bad} bloqueada{bad === 1 ? '' : 's'}</span>
      </div>
      <div className="net-legend-key">
        <span>
          <i className="k ok" /> permitido
        </span>
        <span>
          <i className="k bad" /> bloqueado
        </span>
        <span>
          <i className="k na" /> lo gestiona la nube
        </span>
      </div>
      <p className="small muted">Haz clic en una flecha para permitir o bloquear su tráfico, o en una pieza para ver quién puede entrar.</p>
      <div className="row gap">
        <button className="btn small primary" onClick={() => open('access')}>
          Tabla de accesos
        </button>
        <button className="btn small" onClick={() => open('groups')}>
          Grupos
        </button>
      </div>
    </div>
  );
}

/** Datos para pintar la vista de red en el lienzo. */
export function netViewData(nodes: AppNode[], edges: AppEdge[], a: NetAnalysis) {
  const map = byId(nodes);
  const eMap = new Map<string, { state: 'ok' | 'bad' | 'warn' | 'na'; text: string; title?: string }>();
  for (const e of edges) {
    const v = a.verdicts.get(e.id);
    if (!v || v.kind === 'none' || v.kind === 'managed') {
      eMap.set(e.id, { state: 'na', text: '' });
      continue;
    }
    const err = !v.ok;
    const warn = v.checks.some((c) => !c.ok);
    const port = v.kind === 'egress' ? 'HTTPS' : String(v.port);
    eMap.set(e.id, { state: err ? 'bad' : warn ? 'warn' : 'ok', text: err ? `⛔ ${v.short ?? port}` : `✓ ${port}`, title: v.kind === 'egress' ? 'Salida HTTPS' : portLabel(v.port) });
  }
  const nMap = new Map<string, { port?: number; sgs: { name: string; color: string }[]; relevant: boolean }>();
  for (const n of nodes) {
    if (!isService(n)) continue;
    const vpc = inVpc(n, map);
    const sgs = needsSg(n, map) ? a.net.sgIdsOf(n).map((id) => ({ name: a.net.groups.find((g) => g.id === id)?.name ?? id, color: sgColor(a.net.groups, id) })) : [];
    const touches = edges.some((e) => (e.source === n.id || e.target === n.id) && eMap.get(e.id)?.state !== 'na');
    const role = getService(n.data.serviceId).role;
    nMap.set(n.id, { port: vpc && !isLb(n) && role !== 'netgw' ? listenPort(n) : undefined, sgs, relevant: vpc || touches });
  }
  return { edges: eMap, nodes: nMap };
}

/* ───────────────────────── modal: accesos y grupos */

function AccessTable() {
  const nodes = useStore((s) => s.nodes);
  const edges = useStore((s) => s.edges);
  const a = useNetAnalysis();
  const ct = useCloudText();
  const [onlyBad, setOnlyBad] = useState(false);
  const map = byId(nodes);
  const rows = edges
    .map((e) => ({ e, v: a.verdicts.get(e.id) }))
    .filter((x): x is { e: AppEdge; v: EdgeVerdict } => !!x.v && (x.v.kind === 'connect' || x.v.kind === 'egress'))
    .sort((x, y) => Number(x.v.ok) - Number(y.v.ok));
  const list = onlyBad ? rows.filter((r) => !r.v.ok) : rows;
  const bad = rows.filter((r) => !r.v.ok).length;
  // Reglas que no corresponden a ninguna flecha (accesos extra que agregaste a mano)
  const extras = a.mode === 'manual' ? extraRules(nodes, edges, a) : [];
  if (!rows.length)
    return <p className="muted">No hay conexiones de red que revisar. Las conexiones aparecen cuando hay piezas dentro de una VPC (servidores, balanceadores, bases de datos) conectadas con flechas.</p>;
  return (
    <div className="access-table">
      <div className="row between">
        <span className="muted small">Cada flecha del diagrama que abre una conexión de red. Enciende o apaga el interruptor para permitir o bloquear ese tráfico.</span>
        <div className="seg-choice">
          <button className={!onlyBad ? 'on' : ''} onClick={() => setOnlyBad(false)}>
            Todas ({rows.length})
          </button>
          <button className={onlyBad ? 'on' : ''} onClick={() => setOnlyBad(true)}>
            Bloqueadas ({bad})
          </button>
        </div>
      </div>
      <div className="at-head">
        <span>Origen</span>
        <span>Destino</span>
        <span>Puerto</span>
        <span>Estado</span>
        <span>Permitir</span>
      </div>
      {list.map(({ e, v }) => {
        const { err, warn } = verdictLine(v);
        const allowedBySg = !v.checks.some((c) => !c.ok && c.id.startsWith('sg-'));
        const fix = err && !sgOnly(v) ? err.fix : undefined;
        return (
          <div key={e.id} className={`at-row ${err ? 'bad' : warn ? 'warn' : 'good'}`}>
            <button className="linklike" onClick={() => useStore.getState().focus([e.id, e.source, e.target])}>
              {label(map.get(v.fromId))}
            </button>
            <span>{label(map.get(v.toId))}</span>
            <span className="at-port">{v.kind === 'egress' ? 'HTTPS (salida)' : portLabel(v.port)}</span>
            <span className="at-state">
              {err ? '✗ ' : warn ? '! ' : '✓ '}
              {ct(err ? err.title : warn ? warn.title : 'Conecta')}
              {fix && <FixButton fix={fix} />}
            </span>
            <Switch on={allowedBySg} onChange={(on) => useStore.getState().setAccess(e.id, on)} label={`Permitir ${label(map.get(v.fromId))} → ${label(map.get(v.toId))}`} />
          </div>
        );
      })}
      {extras.length > 0 && (
        <>
          <div className="net-block-title pad-top">Accesos extra (sin flecha en el diagrama)</div>
          {extras.map((x) => (
            <div key={x.key} className="at-row extra">
              <span>{x.from}</span>
              <span>{x.to}</span>
              <span className="at-port">{x.port}</span>
              <span className={`at-state ${x.open ? 'bad' : ''}`}>{x.open ? '⚠ Abierto a todo Internet' : 'Regla manual'}</span>
              <button className="x" title="Quitar esta regla" aria-label="Quitar esta regla" onClick={() => useStore.getState().removeRule(x.sgId, 'inbound', x.ruleId)}>
                ×
              </button>
            </div>
          ))}
        </>
      )}
    </div>
  );
}

function extraRules(nodes: AppNode[], edges: AppEdge[], a: NetAnalysis) {
  const map = byId(nodes);
  const used = new Set<string>();
  // Reglas que justifican alguna flecha
  for (const e of edges) {
    const sem = semantics(e, map);
    if (!sem || sem.kind !== 'connect') continue;
    for (const id of a.net.sgIdsOf(sem.to)) {
      const g = a.net.groups.find((x) => x.id === id);
      g?.inbound.forEach((r) => {
        const ports = isLb(sem.to) ? [sem.port, ...listenersOf(sem.to).map((l) => l.port)] : [sem.port];
        const covers = ports.some((p) => r.protocol === 'all' || (r.from <= p && r.to >= p));
        if (covers && (r.peer.kind !== 'sg' || a.net.sgIdsOf(sem.from).includes(r.peer.sgId) || !inVpc(sem.from, map))) used.add(r.id);
      });
    }
  }
  const out: { key: string; from: string; to: string; port: string; open: boolean; sgId: string; ruleId: string }[] = [];
  const services = nodes.filter(isService);
  for (const g of a.net.groups) {
    const owners = services.filter((n) => a.net.sgIdsOf(n).includes(g.id));
    for (const r of g.inbound) {
      if (used.has(r.id)) continue;
      out.push({
        key: g.id + r.id,
        from: r.peer.kind === 'prefix' ? cdnWord(nodes) : r.peer.kind === 'cidr' ? (isAnyCidr(r.peer.value) ? 'Internet (0.0.0.0/0)' : r.peer.value) : services.filter((n) => a.net.sgIdsOf(n).includes((r.peer as { sgId: string }).sgId)).map((n) => n.data.label).join(', ') || 'grupo sin piezas',
        to: owners.map((n) => n.data.label).join(', ') || g.name,
        port: r.protocol === 'all' ? 'todo' : r.from === r.to ? portLabel(r.from) : `${r.from}–${r.to}`,
        open: r.peer.kind === 'cidr' && isAnyCidr(r.peer.value),
        sgId: g.id,
        ruleId: r.id,
      });
    }
  }
  return out;
}

/** Fila de regla en lenguaje claro: «Permitir [puerto] desde [origen]». */
function RuleRow({ rule, dir, groups, nodes, sgIdsOf, onChange, onDelete }: { rule: SgRule; dir: 'inbound' | 'outbound'; groups: SecurityGroup[]; nodes: AppNode[]; sgIdsOf: (n: ServiceNode) => string[]; onChange: (r: SgRule) => void; onDelete: () => void }) {
  const p = rule.peer;
  const map = byId(nodes);
  const pieces = nodes.filter((n): n is ServiceNode => isService(n) && needsSg(n, map));
  const preset = rule.protocol === 'all' ? 'all' : rule.from === rule.to ? String(rule.from) : 'range';
  const peerValue = p.kind === 'prefix' ? 'cdn' : p.kind === 'cidr' ? (isAnyCidr(p.value) ? 'internet' : 'cidr') : `sg:${p.sgId}`;
  const sgLabel = (g: SecurityGroup) => {
    const users = pieces.filter((n) => sgIdsOf(n).includes(g.id)).map((n) => n.data.label);
    return users.length ? `${users.join(', ')}` : `${g.name} (sin piezas)`;
  };
  return (
    <div className="rule-row">
      <span className="rule-verb">{dir === 'inbound' ? 'Permitir' : 'Salir por'}</span>
      <select
        value={PORT_PRESETS.some((x) => x.protocol !== 'all' && String(x.from) === preset) || preset === 'all' ? preset : preset === 'range' ? 'range' : 'custom'}
        onChange={(e) => {
          const v = e.target.value;
          if (v === 'all') onChange({ ...rule, protocol: 'all', from: 0, to: 65535 });
          else if (v === 'range') onChange({ ...rule, protocol: 'tcp', from: rule.from || 1024, to: Math.max(rule.to, (rule.from || 1024) + 1) });
          else if (v === 'custom') onChange({ ...rule, protocol: 'tcp', from: 9000, to: 9000 });
          else onChange({ ...rule, protocol: 'tcp', from: Number(v), to: Number(v) });
        }}
        aria-label="Puerto"
      >
        {PORT_PRESETS.filter((x) => x.protocol !== 'all').map((x) => (
          <option key={x.label} value={String(x.from)}>
            {x.label} ({x.from})
          </option>
        ))}
        <option value="custom">Otro puerto…</option>
        <option value="range">Rango de puertos…</option>
        <option value="all">Todo el tráfico</option>
      </select>
      {(preset === 'range' || (preset !== 'all' && !PORT_PRESETS.some((x) => String(x.from) === preset))) && (
        <span className="rule-ports">
          <input type="number" min={0} max={65535} value={rule.from} onChange={(e) => onChange({ ...rule, from: Number(e.target.value), to: preset === 'range' ? rule.to : Number(e.target.value) })} aria-label="Puerto" />
          {preset === 'range' && (
            <>
              –<input type="number" min={0} max={65535} value={rule.to} onChange={(e) => onChange({ ...rule, to: Number(e.target.value) })} aria-label="Hasta" />
            </>
          )}
        </span>
      )}
      <span className="rule-verb">{dir === 'inbound' ? 'desde' : 'hacia'}</span>
      <select
        value={peerValue}
        onChange={(e) => {
          const v = e.target.value;
          const peer: SgSource = v === 'cdn' ? { kind: 'prefix', value: 'cdn' } : v === 'internet' ? { kind: 'cidr', value: '0.0.0.0/0' } : v === 'cidr' ? { kind: 'cidr', value: '10.0.0.0/16' } : { kind: 'sg', sgId: v.slice(3) };
          onChange({ ...rule, peer });
        }}
        aria-label="Origen"
      >
        <optgroup label="Piezas (por su grupo)">
          {groups.map((g) => (
            <option key={g.id} value={`sg:${g.id}`}>
              {sgLabel(g)}
            </option>
          ))}
        </optgroup>
        <optgroup label="Otros">
          <option value="cdn">{cdnWord(nodes)}</option>
          <option value="internet">Cualquier IP de Internet</option>
          <option value="cidr">Un rango de IPs…</option>
        </optgroup>
      </select>
      {p.kind === 'cidr' && !isAnyCidr(p.value) && <input className={`cidr ${/^\d+\.\d+\.\d+\.\d+\/\d+$/.test(p.value.trim()) ? '' : 'invalid'}`} value={p.value} onChange={(e) => onChange({ ...rule, peer: { kind: 'cidr', value: e.target.value } })} aria-label="Rango CIDR" />}
      <button className="x" onClick={onDelete} aria-label="Quitar regla">
        ×
      </button>
    </div>
  );
}

function GroupsEditor() {
  const nodes = useStore((s) => s.nodes);
  const edges = useStore((s) => s.edges);
  const groups = useStore((s) => s.securityGroups);
  const { editSecurityGroups, setNet, ensureManualNet } = useStore.getState();
  const eff = useMemo(() => effectiveNet(nodes, edges, groups), [nodes, edges, groups]);
  const want = useNetUi((s) => s.sgId);
  const [selId, setSelId] = useState<string | null>(want);
  const sel = eff.groups.find((g) => g.id === selId) ?? eff.groups[0];
  const map = byId(nodes);
  const SG = sgWord(nodes);
  const vpcPieces = nodes.filter((n): n is ServiceNode => isService(n) && needsSg(n, map));
  const users = (g: SecurityGroup) => vpcPieces.filter((n) => eff.sgIdsOf(n).includes(g.id));
  if (!eff.groups.length) return <p className="muted">No hay piezas dentro de una VPC/VNet, así que no hacen falta {SG}s.</p>;
  const update = (fn: (g: SecurityGroup) => SecurityGroup, key?: string) => sel && editSecurityGroups((gs) => gs.map((x) => (x.id === sel.id ? fn(x) : x)), key ? `${sel.id}:${key}` : undefined);
  return (
    <div className="sg-layout">
      <div className="sg-list">
        <div className="small muted">Un {SG} es un conjunto de reglas que se aplica a una o varias piezas.</div>
        {eff.groups.map((g) => (
          <button key={g.id} className={`sg-item ${sel?.id === g.id ? 'on' : ''}`} onClick={() => setSelId(g.id)} style={{ ['--sg' as string]: sgColor(eff.groups, g.id) }}>
            <b>{users(g).map((n) => n.data.label).join(', ') || g.name}</b>
            <span>
              {g.name} · {g.inbound.length} regla{g.inbound.length === 1 ? '' : 's'} de entrada
            </span>
          </button>
        ))}
        <button
          className="btn small"
          onClick={() => {
            const id = uid('sg');
            editSecurityGroups((gs) => [...gs, { id, name: `${SG === 'NSG' ? 'nsg' : 'sg'}-nuevo-${gs.length + 1}`, inbound: [], outbound: [{ id: uid('r'), protocol: 'all', from: 0, to: 65535, peer: { kind: 'cidr', value: '0.0.0.0/0' } }] }]);
            setSelId(id);
          }}
        >
          + Nuevo {SG}
        </button>
      </div>
      {sel && (
        <div className="sg-detail">
          <div className="row gap">
            <label className="field">
              <span className="field-label">Nombre</span>
              <input value={sel.name} onChange={(e) => update((g) => ({ ...g, name: e.target.value }), 'name')} />
            </label>
            <label className="field">
              <span className="field-label">Para qué es</span>
              <input value={sel.description ?? ''} placeholder="Ej.: tráfico hacia la app" onChange={(e) => update((g) => ({ ...g, description: e.target.value }), 'desc')} />
            </label>
          </div>
          <div className="sg-rules">
            <div className="sg-rules-head">
              <b>Se aplica a</b>
            </div>
            <div className="sg-assign">
              {vpcPieces.map((n) => {
                const on = eff.sgIdsOf(n).includes(sel.id);
                return (
                  <label key={n.id} className={`assign-chip ${on ? 'on' : ''}`}>
                    <input
                      type="checkbox"
                      checked={on}
                      onChange={(e) => {
                        ensureManualNet();
                        const cur = (useStore.getState().nodes.find((x) => x.id === n.id) as ServiceNode).data.net?.sgIds ?? [];
                        setNet(n.id, { sgIds: e.target.checked ? [...cur, sel.id] : cur.filter((x) => x !== sel.id) });
                      }}
                    />
                    {n.data.label} <em>:{isLb(n) ? listenersOf(n).map((l) => l.port).join('/') : listenPort(n)}</em>
                  </label>
                );
              })}
            </div>
          </div>
          {(['inbound', 'outbound'] as const).map((dir) => (
            <div key={dir} className="sg-rules">
              <div className="sg-rules-head">
                <b>{dir === 'inbound' ? 'Quién puede entrar' : 'A dónde puede salir'}</b>
                <button
                  className="btn small"
                  onClick={() => {
                    const other = eff.groups.find((g) => g.id !== sel.id);
                    const peer: SgSource = dir === 'outbound' ? { kind: 'cidr', value: '0.0.0.0/0' } : other ? { kind: 'sg', sgId: other.id } : { kind: 'cidr', value: '10.0.0.0/16' };
                    const port = dir === 'outbound' ? 443 : (users(sel)[0] ? listenPort(users(sel)[0]) : 443);
                    update((g) => ({ ...g, [dir]: [...g[dir], { id: uid('r'), protocol: 'tcp', from: port, to: port, peer }] }));
                  }}
                >
                  + Regla
                </button>
              </div>
              {sel[dir].length === 0 && <div className="empty-note">{dir === 'inbound' ? 'Nadie puede entrar.' : 'No puede salir a ningún lado.'}</div>}
              {sel[dir].map((r) => (
                <RuleRow
                  key={r.id}
                  rule={r}
                  dir={dir}
                  groups={eff.groups}
                  nodes={nodes}
                  sgIdsOf={eff.sgIdsOf}
                  onChange={(nr) => update((g) => ({ ...g, [dir]: g[dir].map((x) => (x.id === r.id ? nr : x)) }), r.id)}
                  onDelete={() => update((g) => ({ ...g, [dir]: g[dir].filter((x) => x.id !== r.id) }))}
                />
              ))}
            </div>
          ))}
          <button className="btn danger small" onClick={() => window.confirm(`¿Eliminar ${sel.name}?`) && (editSecurityGroups((gs) => gs.filter((g) => g.id !== sel.id)), setSelId(null))}>
            Eliminar {SG}
          </button>
        </div>
      )}
    </div>
  );
}

export function NetModal({ onClose }: { onClose: () => void }) {
  const nodes = useStore((s) => s.nodes);
  const tab = useNetUi((s) => s.tab);
  const setTab = useNetUi((s) => s.setTab);
  const a = useNetAnalysis();
  const bad = [...a.verdicts.values()].filter((v) => !v.ok).length;
  return (
    <Modal title="Red" onClose={onClose} wide>
      <ModeLine />
      <div className="net-tabs" role="tablist">
        <button role="tab" aria-selected={tab === 'access'} className={tab === 'access' ? 'on' : ''} onClick={() => setTab('access')}>
          Accesos {bad > 0 && <span className="count bad">{bad}</span>}
        </button>
        <button role="tab" aria-selected={tab === 'groups'} className={tab === 'groups' ? 'on' : ''} onClick={() => setTab('groups')}>
          {sgWord(nodes)}s (avanzado)
        </button>
      </div>
      {tab === 'access' ? <AccessTable /> : <GroupsEditor />}
    </Modal>
  );
}
