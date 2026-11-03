import { useMemo, useState } from 'react';
import { create } from 'zustand';
import { getService, primaryCloud } from '../catalog/catalog';
import { byId, isService, placementOf, uid } from '../lib/graph';
import { useCloudText } from '../lib/useCloud';
import { defaultPort, effectiveNet, inVpc, isLb, listenersOf, listenPort, needsSg, originProtocol, PORT_PRESETS, ruleText, targetOf } from '../net/model';
import { analyzeNetwork, type EdgeVerdict } from '../net/reach';
import { useStore } from '../store';
import type { AppEdge, Listener, NetFix, SecurityGroup, ServiceNode, SgRule, SgSource } from '../types';
import { Modal } from './Modals';

/* ───────────────────────── estado UI del editor de SG */

export const useNetUi = create<{ sgId: string | null; setSg: (id: string | null) => void }>((set) => ({ sgId: null, setSg: (id) => set({ sgId: id }) }));
export const openNetEditor = (sgId: string | null = null) => {
  useNetUi.getState().setSg(sgId);
  window.dispatchEvent(new CustomEvent('archiplan:open', { detail: 'net' }));
};

/** Análisis de red memorizado para la UI. */
function useNetAnalysis() {
  const nodes = useStore((s) => s.nodes);
  const edges = useStore((s) => s.edges);
  const groups = useStore((s) => s.securityGroups);
  return useMemo(() => analyzeNetwork(nodes, edges, groups), [nodes, edges, groups]);
}

function FixButton({ fix }: { fix: NetFix }) {
  return (
    <button className="btn small fix" onClick={() => useStore.getState().applyNetFix(fix)}>
      ⚡ {fix.label}
    </button>
  );
}

function VerdictRow({ v, edge, selfId }: { v: EdgeVerdict; edge: AppEdge; selfId?: string }) {
  const nodes = useStore((s) => s.nodes);
  const ct = useCloudText();
  const map = byId(nodes);
  const other = map.get(edge.source === selfId ? edge.target : edge.source);
  const err = v.checks.find((c) => !c.ok && c.severity === 'error');
  const warn = v.checks.find((c) => !c.ok && c.severity === 'warn');
  const dir = selfId ? (edge.source === selfId ? '→' : '←') : '';
  return (
    <div className={`net-verdict ${err ? 'bad' : warn ? 'warn' : 'good'}`}>
      <button className="linklike net-v-head" onClick={() => useStore.getState().focus([edge.id, edge.source, edge.target])}>
        <span className="net-v-ico">{err ? '✗' : warn ? '!' : '✓'}</span>
        <span>
          {dir} {(other?.data as { label?: string })?.label}
          {v.port ? <em> :{v.port}</em> : null}
        </span>
      </button>
      <span className="net-v-text">{ct(err ? err.title : warn ? warn.title : v.summary)}</span>
      {err && <span className="muted small">{ct(err.detail)}</span>}
      {(err ?? warn)?.fix && <FixButton fix={(err ?? warn)!.fix!} />}
    </div>
  );
}

/* ───────────────────────── sección «Red» del inspector de una pieza */

export function NetSection({ node }: { node: ServiceNode }) {
  const nodes = useStore((s) => s.nodes);
  const edges = useStore((s) => s.edges);
  const groups = useStore((s) => s.securityGroups);
  const { setNet, materializeSecurityGroups } = useStore.getState();
  const a = useNetAnalysis();
  const map = byId(nodes);
  const def = getService(node.data.serviceId);
  const azure = primaryCloud(nodes) === 'azure';
  const SG = azure ? 'NSG' : 'Security Group';
  const vpc = inVpc(node, map);
  const lb = isLb(node);
  const cdn = def.role === 'cdn';
  const sgable = needsSg(node, map);
  const mine = edges.filter((e) => e.source === node.id || e.target === node.id).map((e) => ({ e, v: a.verdicts.get(e.id) })).filter((x): x is { e: AppEdge; v: EdgeVerdict } => !!x.v && x.v.kind !== 'none' && x.v.kind !== 'managed');
  if (!vpc && !cdn && !mine.length) return null;
  const net = node.data.net ?? {};
  const eff = effectiveNet(nodes, edges, groups);
  const assigned = eff.sgIdsOf(node).map((id) => eff.groups.find((g) => g.id === id)).filter((g): g is SecurityGroup => !!g);
  const manual = a.mode === 'manual';
  const listens = !lb && !cdn && vpc && !['netgw'].includes(def.role);
  const publicSubnet = placementOf(node, map) === 'subnet-public' && def.role === 'compute';
  const cdnName = azure ? 'Front Door' : 'CloudFront';

  return (
    <div className="insp-section net-section">
      <div className="insp-section-title row between">
        <span>Red y seguridad</span>
        <span className={`net-mode ${a.mode}`} title={manual ? 'Usas tus propios grupos' : 'Grupos derivados de las flechas (mínimo privilegio)'}>
          {manual ? 'Manual' : 'Automático'}
        </span>
      </div>

      {listens && (
        <label className="field">
          <span className="field-label">Puerto en el que escucha</span>
          <div className="row gap">
            <input type="number" min={1} max={65535} placeholder={String(defaultPort(node))} value={net.port ?? ''} onChange={(e) => setNet(node.id, { port: e.target.value === '' ? undefined : Math.max(1, Math.min(65535, Number(e.target.value))) }, 'port')} />
            <select value="" onChange={(e) => e.target.value && setNet(node.id, { port: Number(e.target.value) })} aria-label="Puertos comunes">
              <option value="">Comunes…</option>
              {[80, 443, 3000, 8080, 8443, 5432, 3306, 1433, 6379, 27017].map((p) => (
                <option key={p} value={p}>
                  {p}
                </option>
              ))}
            </select>
          </div>
          <span className="field-help">Por defecto {defaultPort(node)}. Los balanceadores y {SG} deben apuntar a este puerto.</span>
        </label>
      )}

      {publicSubnet && (
        <label className="toggle">
          <input type="checkbox" checked={!!net.publicIp} onChange={(e) => setNet(node.id, { publicIp: e.target.checked })} />
          <span>IP pública (acceso directo desde Internet)</span>
        </label>
      )}

      {cdn && (
        <label className="field">
          <span className="field-label">Protocolo hacia el origen</span>
          <select value={originProtocol(node)} onChange={(e) => setNet(node.id, { originProtocol: e.target.value as 'https-only' })}>
            <option value="https-only">Solo HTTPS (recomendado)</option>
            <option value="http-only">Solo HTTP</option>
            <option value="match-viewer">Igual que el cliente</option>
          </select>
        </label>
      )}

      {lb && <LbEditor node={node} />}

      {sgable && (
        <div className="net-sgs">
          <span className="field-label">{SG}s asignados</span>
          <div className="chips">
            {assigned.map((g) => (
              <span key={g.id} className="sg-chip">
                <button className="linklike" onClick={() => openNetEditor(g.id)}>
                  {g.name}
                </button>
                {manual && (
                  <button className="x" aria-label={`Quitar ${g.name}`} onClick={() => setNet(node.id, { sgIds: (net.sgIds ?? []).filter((x) => x !== g.id) })}>
                    ×
                  </button>
                )}
              </span>
            ))}
            {!assigned.length && <span className="muted small">Ninguno: se usaría el grupo por defecto.</span>}
          </div>
          {manual ? (
            <select
              value=""
              onChange={(e) => {
                if (e.target.value === '__new') {
                  useStore.getState().applyNetFix({ kind: 'create-sg', nodeId: node.id, label: `Nuevo ${SG}` });
                  return;
                }
                if (e.target.value) setNet(node.id, { sgIds: [...(net.sgIds ?? []), e.target.value] });
              }}
            >
              <option value="">+ Asignar {SG}…</option>
              {groups
                .filter((g) => !(net.sgIds ?? []).includes(g.id))
                .map((g) => (
                  <option key={g.id} value={g.id}>
                    {g.name}
                  </option>
                ))}
              <option value="__new">+ Crear uno nuevo para esta pieza</option>
            </select>
          ) : (
            <button className="btn small" onClick={() => (materializeSecurityGroups(), openNetEditor(`sg_${node.id}`))}>
              ✎ Configurar los {SG}s yo mismo
            </button>
          )}
          {assigned.map((g) => (
            <div key={g.id} className="sg-rules-mini">
              <b>{g.name}</b> · entrada:
              {g.inbound.length ? (
                <ul>
                  {g.inbound.map((r) => (
                    <li key={r.id}>{ruleText(r, eff.groups, cdnName)}</li>
                  ))}
                </ul>
              ) : (
                <span className="muted"> sin reglas (nada entra)</span>
              )}
            </div>
          ))}
        </div>
      )}

      {mine.length > 0 && (
        <div className="net-conns">
          <span className="field-label">Conectividad de sus flechas</span>
          {mine.map(({ e, v }) => (
            <VerdictRow key={e.id} v={v} edge={e} selfId={node.id} />
          ))}
        </div>
      )}
    </div>
  );
}

function LbEditor({ node }: { node: ServiceNode }) {
  const nodes = useStore((s) => s.nodes);
  const edges = useStore((s) => s.edges);
  const { setNet } = useStore.getState();
  const map = byId(nodes);
  const ls = listenersOf(node);
  const nlb = node.data.serviceId === 'nlb';
  const setLs = (next: Listener[]) => setNet(node.id, { listeners: next }, 'listeners');
  const targets = edges.filter((e) => e.source === node.id).map((e) => map.get(e.target)).filter((n): n is ServiceNode => isService(n) && ['compute', 'workflow'].includes(getService(n.data.serviceId).role));
  return (
    <>
      <div className="field">
        <span className="field-label">Listeners</span>
        <div className="net-table">
          {ls.map((l) => (
            <div key={l.id} className="net-row">
              <select value={l.protocol} onChange={(e) => setLs(ls.map((x) => (x.id === l.id ? { ...x, protocol: e.target.value as Listener['protocol'] } : x)))}>
                {(nlb ? ['TCP', 'TLS'] : ['HTTPS', 'HTTP']).map((p) => (
                  <option key={p}>{p}</option>
                ))}
              </select>
              <input type="number" min={1} max={65535} value={l.port} onChange={(e) => setLs(ls.map((x) => (x.id === l.id ? { ...x, port: Number(e.target.value) } : x)))} aria-label="Puerto" />
              <select value={l.action} onChange={(e) => setLs(ls.map((x) => (x.id === l.id ? { ...x, action: e.target.value as Listener['action'] } : x)))} aria-label="Acción">
                <option value="forward">reenvía</option>
                {!nlb && <option value="redirect-https">redirige a HTTPS</option>}
              </select>
              {(l.protocol === 'HTTPS' || l.protocol === 'TLS') && (
                <label className="mini-check" title="Certificado TLS asociado">
                  <input type="checkbox" checked={!!l.cert} onChange={(e) => setLs(ls.map((x) => (x.id === l.id ? { ...x, cert: e.target.checked } : x)))} /> cert
                </label>
              )}
              <button className="x" aria-label="Quitar listener" onClick={() => setLs(ls.filter((x) => x.id !== l.id))}>
                ×
              </button>
            </div>
          ))}
          <button className="btn small" onClick={() => setLs([...ls, { id: uid('l'), port: 8443, protocol: nlb ? 'TCP' : 'HTTPS', action: 'forward', cert: !nlb }])}>
            + Listener
          </button>
        </div>
      </div>
      {targets.length > 0 && (
        <div className="field">
          <span className="field-label">Target groups</span>
          <div className="net-table">
            {targets.map((t) => {
              const tg = targetOf(node, t);
              const set = (p: Partial<typeof tg>) => setNet(node.id, { targets: { ...(node.data.net?.targets ?? {}), [t.id]: { ...tg, ...p } } }, `tg:${t.id}`);
              const mismatch = tg.port !== listenPort(t);
              return (
                <div key={t.id} className={`net-row tg ${mismatch ? 'bad' : ''}`}>
                  <span className="tg-name" title={t.data.label}>
                    → {t.data.label}
                  </span>
                  <select value={tg.protocol} onChange={(e) => set({ protocol: e.target.value as typeof tg.protocol })}>
                    {(nlb ? ['TCP'] : ['HTTP', 'HTTPS']).map((p) => (
                      <option key={p}>{p}</option>
                    ))}
                  </select>
                  <input type="number" min={1} max={65535} value={tg.port} onChange={(e) => set({ port: Number(e.target.value) })} aria-label="Puerto del target" title={mismatch ? `${t.data.label} escucha en ${listenPort(t)}` : undefined} />
                  {!nlb && <input value={tg.healthPath} onChange={(e) => set({ healthPath: e.target.value })} placeholder="/health" aria-label="Ruta de health check" />}
                </div>
              );
            })}
          </div>
        </div>
      )}
    </>
  );
}

/* ───────────────────────── sección de red de una flecha */

export function EdgeNetSection({ edge }: { edge: AppEdge }) {
  const a = useNetAnalysis();
  const ct = useCloudText();
  const v = a.verdicts.get(edge.id);
  if (!v || v.kind === 'none') return null;
  if (v.kind === 'managed')
    return (
      <div className="insp-section">
        <div className="insp-section-title">Red</div>
        <div className="muted small">La invoca la nube (evento / servicio administrado): no pasa por Security Groups.</div>
      </div>
    );
  return (
    <div className="insp-section net-section">
      <div className="insp-section-title">Red · {v.kind === 'egress' ? `salida HTTPS` : `TCP ${v.port}`}</div>
      <div className={`net-status ${v.ok ? 'good' : 'bad'}`}>{v.ok ? '✓ La conexión pasa con la configuración actual' : `✗ Bloqueada${v.failure ? ` → ${v.failure}` : ''}`}</div>
      <ul className="net-checks">
        {v.checks.map((c) => (
          <li key={c.id} className={c.ok ? 'ok' : c.severity}>
            <span>{c.ok ? '✓' : c.severity === 'error' ? '✗' : '!'}</span>
            <div>
              <b>{ct(c.title)}</b>
              {!c.ok && c.detail && <div className="muted small">{ct(c.detail)}</div>}
              {!c.ok && c.fix && <FixButton fix={c.fix} />}
            </div>
          </li>
        ))}
        {!v.checks.length && <li className="ok"><span>✓</span><div>Sin restricciones de red aplicables.</div></li>}
      </ul>
    </div>
  );
}

/* ───────────────────────── editor de Security Groups */

const sourceKinds: { id: SgSource['kind']; label: string }[] = [
  { id: 'sg', label: 'Security Group' },
  { id: 'cidr', label: 'CIDR' },
  { id: 'prefix', label: 'CDN (prefix list)' },
];

function RuleEditor({ rule, groups, onChange, onDelete, cdnName }: { rule: SgRule; groups: SecurityGroup[]; onChange: (r: SgRule) => void; onDelete: () => void; cdnName: string }) {
  const p = rule.peer;
  return (
    <div className="sg-rule">
      <select value={rule.protocol} onChange={(e) => onChange({ ...rule, protocol: e.target.value as SgRule['protocol'], ...(e.target.value === 'all' ? { from: 0, to: 65535 } : {}) })} aria-label="Protocolo">
        <option value="tcp">TCP</option>
        <option value="udp">UDP</option>
        <option value="all">Todo</option>
      </select>
      <input type="number" min={0} max={65535} disabled={rule.protocol === 'all'} value={rule.from} onChange={(e) => onChange({ ...rule, from: Number(e.target.value), to: Math.max(Number(e.target.value), rule.to === rule.from ? Number(e.target.value) : rule.to) })} aria-label="Desde puerto" />
      <input type="number" min={0} max={65535} disabled={rule.protocol === 'all'} value={rule.to} onChange={(e) => onChange({ ...rule, to: Number(e.target.value) })} aria-label="Hasta puerto" />
      <select
        value={p.kind}
        onChange={(e) => {
          const k = e.target.value as SgSource['kind'];
          onChange({ ...rule, peer: k === 'cidr' ? { kind: 'cidr', value: '10.0.0.0/16' } : k === 'prefix' ? { kind: 'prefix', value: 'cdn' } : { kind: 'sg', sgId: groups[0]?.id ?? '' } });
        }}
        aria-label="Tipo de origen"
      >
        {sourceKinds.map((s) => (
          <option key={s.id} value={s.id}>
            {s.id === 'prefix' ? `${cdnName} (prefix list)` : s.label}
          </option>
        ))}
      </select>
      {p.kind === 'cidr' && <input className={/^\d+\.\d+\.\d+\.\d+\/\d+$/.test(p.value.trim()) ? '' : 'invalid'} value={p.value} onChange={(e) => onChange({ ...rule, peer: { kind: 'cidr', value: e.target.value } })} aria-label="CIDR" />}
      {p.kind === 'sg' && (
        <select value={p.sgId} onChange={(e) => onChange({ ...rule, peer: { kind: 'sg', sgId: e.target.value } })} aria-label="Security Group de origen">
          {!groups.some((g) => g.id === p.sgId) && <option value={p.sgId}>(eliminado)</option>}
          {groups.map((g) => (
            <option key={g.id} value={g.id}>
              {g.name}
            </option>
          ))}
        </select>
      )}
      {p.kind === 'prefix' && <span className="muted small">IPs de {cdnName}</span>}
      <input className="desc" value={rule.description ?? ''} placeholder="Descripción" onChange={(e) => onChange({ ...rule, description: e.target.value })} />
      <button className="x" onClick={onDelete} aria-label="Quitar regla">
        ×
      </button>
    </div>
  );
}

export function NetModal({ onClose }: { onClose: () => void }) {
  const nodes = useStore((s) => s.nodes);
  const edges = useStore((s) => s.edges);
  const groups = useStore((s) => s.securityGroups);
  const { setSecurityGroups, setNet, materializeSecurityGroups, resetSecurityGroups } = useStore.getState();
  const azure = primaryCloud(nodes) === 'azure';
  const SG = azure ? 'NSG' : 'Security Group';
  const cdnName = azure ? 'Front Door' : 'CloudFront';
  const eff = useMemo(() => effectiveNet(nodes, edges, groups), [nodes, edges, groups]);
  const a = useMemo(() => analyzeNetwork(nodes, edges, groups), [nodes, edges, groups]);
  const manual = eff.mode === 'manual';
  const want = useNetUi((s) => s.sgId);
  const [selId, setSelId] = useState<string | null>(want);
  const sel = eff.groups.find((g) => g.id === selId) ?? eff.groups[0];
  const map = byId(nodes);
  const vpcPieces = nodes.filter((n): n is ServiceNode => isService(n) && needsSg(n, map));
  const blocked = [...a.verdicts.values()].filter((v) => !v.ok);
  const users = (g: SecurityGroup) => vpcPieces.filter((n) => eff.sgIdsOf(n).includes(g.id));

  const update = (g: SecurityGroup, key?: string) => setSecurityGroups(groups.map((x) => (x.id === g.id ? g : x)), key ? `${g.id}:${key}` : undefined);
  const addRule = (dir: 'inbound' | 'outbound', preset = PORT_PRESETS[0]) => {
    if (!sel) return;
    const peer: SgSource = dir === 'outbound' ? { kind: 'cidr', value: '0.0.0.0/0' } : { kind: 'sg', sgId: groups.find((g) => g.id !== sel.id)?.id ?? sel.id };
    update({ ...sel, [dir]: [...sel[dir], { id: uid('r'), protocol: preset.protocol, from: preset.from, to: preset.to, peer }] });
  };

  return (
    <Modal title={`Red y ${SG}s`} onClose={onClose} wide>
      <div className={`net-banner ${eff.mode}`}>
        {manual ? (
          <>
            <div>
              <b>Modo manual.</b> El análisis, las simulaciones y el Terraform usan exactamente los {SG}s que definas aquí. Si algo queda mal, la flecha se marca en rojo y la «Petición de usuario» te dice dónde falla.
            </div>
            <div className="row gap">
              <button className="btn small" onClick={() => window.confirm(`Se reemplazarán tus ${SG}s por los generados desde el diagrama. ¿Continuar?`) && materializeSecurityGroups()}>
                ↻ Regenerar desde el diagrama
              </button>
              <button className="btn small" onClick={() => window.confirm(`Se borrarán tus ${SG}s y se volverá a derivarlos de las flechas. ¿Continuar?`) && resetSecurityGroups()}>
                Volver a automático
              </button>
            </div>
          </>
        ) : (
          <>
            <div>
              <b>Modo automático.</b> Cada pieza en la VPC recibe un {SG} con lo mínimo que piden sus flechas. Pasa a modo manual para configurar tú mismo puertos, orígenes y asignaciones.
            </div>
            <button className="btn primary small" onClick={materializeSecurityGroups}>
              ✎ Configurar manualmente (partir de estos)
            </button>
          </>
        )}
      </div>
      {blocked.length > 0 && (
        <div className="net-blocked">
          <b>
            {blocked.length} conexión{blocked.length > 1 ? 'es' : ''} bloqueada{blocked.length > 1 ? 's' : ''}:
          </b>
          {blocked.map((v) => (
            <div key={v.edgeId} className="net-blocked-row">
              <span>
                {(map.get(v.fromId)?.data as { label: string })?.label} → {(map.get(v.toId)?.data as { label: string })?.label}: {v.summary}
              </span>
              {v.checks.find((c) => !c.ok && c.fix && c.severity === 'error')?.fix && <FixButton fix={v.checks.find((c) => !c.ok && c.fix && c.severity === 'error')!.fix!} />}
            </div>
          ))}
        </div>
      )}
      {!eff.groups.length ? (
        <p className="muted">No hay piezas dentro de una VPC/VNet: no hacen falta {SG}s. Agrega una VPC con subnets y coloca ahí tus servidores, balanceadores y bases de datos.</p>
      ) : (
        <div className="sg-layout">
          <div className="sg-list">
            {eff.groups.map((g) => (
              <button key={g.id} className={`sg-item ${sel?.id === g.id ? 'on' : ''}`} onClick={() => setSelId(g.id)}>
                <b>{g.name}</b>
                <span>
                  {g.inbound.length} entrada · {users(g).length ? users(g).map((n) => n.data.label).join(', ') : 'sin asignar'}
                </span>
              </button>
            ))}
            {manual && (
              <button
                className="btn small"
                onClick={() => {
                  const g: SecurityGroup = { id: uid('sg'), name: `${azure ? 'nsg' : 'sg'}-nuevo-${groups.length + 1}`, inbound: [], outbound: [{ id: uid('r'), protocol: 'all', from: 0, to: 65535, peer: { kind: 'cidr', value: '0.0.0.0/0' } }] };
                  setSecurityGroups([...groups, g]);
                  setSelId(g.id);
                }}
              >
                + Nuevo {SG}
              </button>
            )}
          </div>
          {sel && (
            <div className={`sg-detail ${manual ? '' : 'readonly'}`}>
              <div className="row gap">
                <label className="field">
                  <span className="field-label">Nombre</span>
                  <input value={sel.name} disabled={!manual} onChange={(e) => update({ ...sel, name: e.target.value }, 'name')} />
                </label>
                <label className="field">
                  <span className="field-label">Descripción</span>
                  <input value={sel.description ?? ''} disabled={!manual} onChange={(e) => update({ ...sel, description: e.target.value }, 'desc')} />
                </label>
              </div>
              {(['inbound', 'outbound'] as const).map((dir) => (
                <div key={dir} className="sg-rules">
                  <div className="sg-rules-head">
                    <b>{dir === 'inbound' ? 'Reglas de entrada' : 'Reglas de salida'}</b>
                    <span className="muted small">{dir === 'inbound' ? 'Quién puede conectarse a las piezas de este grupo' : 'A dónde pueden conectarse'}</span>
                    {manual && (
                      <select value="" onChange={(e) => e.target.value !== '' && addRule(dir, PORT_PRESETS[Number(e.target.value)])} aria-label="Agregar regla">
                        <option value="">+ Regla…</option>
                        {PORT_PRESETS.map((p, i) => (
                          <option key={p.label} value={i}>
                            {p.label} {p.protocol === 'all' ? '' : `(${p.from})`}
                          </option>
                        ))}
                      </select>
                    )}
                  </div>
                  {sel[dir].length === 0 && <div className="muted small pad-y">Sin reglas: {dir === 'inbound' ? 'no entra nada.' : 'no sale nada.'}</div>}
                  {manual
                    ? sel[dir].map((r) => (
                        <RuleEditor
                          key={r.id}
                          rule={r}
                          groups={groups}
                          cdnName={cdnName}
                          onChange={(nr) => update({ ...sel, [dir]: sel[dir].map((x) => (x.id === r.id ? nr : x)) }, r.id)}
                          onDelete={() => update({ ...sel, [dir]: sel[dir].filter((x) => x.id !== r.id) })}
                        />
                      ))
                    : sel[dir].map((r) => (
                        <div key={r.id} className="sg-rule ro">
                          {ruleText(r, eff.groups, cdnName)}
                          {r.description ? <span className="muted"> — {r.description}</span> : null}
                        </div>
                      ))}
                </div>
              ))}
              <div className="sg-rules">
                <div className="sg-rules-head">
                  <b>Asignado a</b>
                </div>
                <div className="sg-assign">
                  {vpcPieces.map((n) => {
                    const on = eff.sgIdsOf(n).includes(sel.id);
                    return (
                      <label key={n.id} className={`toggle ${manual ? '' : 'disabled'}`}>
                        <input type="checkbox" disabled={!manual} checked={on} onChange={(e) => setNet(n.id, { sgIds: e.target.checked ? [...(n.data.net?.sgIds ?? []), sel.id] : (n.data.net?.sgIds ?? []).filter((x) => x !== sel.id) })} />
                        <span>
                          {n.data.label} <em className="muted">· escucha en {isLb(n) ? listenersOf(n).map((l) => l.port).join('/') : listenPort(n)}</em>
                        </span>
                      </label>
                    );
                  })}
                </div>
              </div>
              {manual && (
                <button className="btn danger small" onClick={() => window.confirm(`¿Eliminar ${sel.name}?`) && (setSecurityGroups(groups.filter((g) => g.id !== sel.id)), setSelId(null))}>
                  Eliminar {SG}
                </button>
              )}
            </div>
          )}
        </div>
      )}
    </Modal>
  );
}
