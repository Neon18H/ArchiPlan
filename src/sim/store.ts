import { create } from 'zustand';
import { useStore } from '../store';
import { simulate, type SimResult } from './engine';
import { defaultScenario, SCENARIO_MAP, type Scenario, type ScenarioKind } from './scenarios';

interface SimState {
  open: boolean;
  scenario: Scenario;
  result: SimResult | null;
  idx: number;
  playing: boolean;
  speed: number;
  setOpen: (v: boolean) => void;
  setKind: (k: ScenarioKind) => void;
  patch: (p: Partial<Scenario>) => void;
  run: () => void;
  setIdx: (i: number) => void;
  setPlaying: (v: boolean) => void;
  setSpeed: (v: number) => void;
}

export const useSim = create<SimState>((set, get) => ({
  open: false,
  scenario: defaultScenario('spike'),
  result: null,
  idx: 0,
  playing: false,
  speed: 4,
  setOpen: (v) => {
    set({ open: v, playing: false });
    if (v) get().run();
  },
  setKind: (k) => {
    const prevTarget = get().scenario.targetId;
    const keepTarget = SCENARIO_MAP[k].target && SCENARIO_MAP[k].target === SCENARIO_MAP[get().scenario.kind].target;
    set({ scenario: { ...defaultScenario(k), targetId: keepTarget ? prevTarget : '' }, idx: 0, result: null, playing: false });
    get().run();
  },
  patch: (p) => {
    set({ scenario: { ...get().scenario, ...p } });
    get().run();
  },
  run: () => {
    const { nodes, edges } = useStore.getState();
    const result = simulate(nodes, edges, get().scenario);
    const prev = get().result;
    // Al re-simular, mantener el instante elegido si sigue existiendo
    const idx = prev && get().idx < result.frames.length ? get().idx : defaultIdx(result);
    set({ result, idx });
  },
  setIdx: (i) => set({ idx: Math.max(0, Math.min(i, (get().result?.frames.length ?? 1) - 1)) }),
  setPlaying: (v) => set({ playing: v }),
  setSpeed: (v) => set({ speed: v }),
}));

/** Instante inicial: el peor momento del escenario (lo más interesante de ver). */
function defaultIdx(r: SimResult): number {
  let worst = 0;
  r.frames.forEach((f, i) => {
    if (f.success < r.frames[worst].success - 1e-9) worst = i;
  });
  if (r.frames[worst].success >= 0.999) {
    // Sin errores: mostrar el momento de más carga
    let peak = 0;
    r.frames.forEach((f, i) => {
      if (f.legitOffered + f.attackSent > r.frames[peak].legitOffered + r.frames[peak].attackSent) peak = i;
    });
    return peak;
  }
  return worst;
}

// Re-simular cuando cambia el diagrama (con el panel abierto)
let timer: ReturnType<typeof setTimeout> | undefined;
useStore.subscribe((s, prev) => {
  if (!useSim.getState().open) return;
  if (s.nodes === prev.nodes && s.edges === prev.edges) return;
  const changed =
    s.edges !== prev.edges ||
    s.nodes.length !== prev.nodes.length ||
    s.nodes.some((n, i) => n.data !== prev.nodes[i]?.data || n.parentId !== prev.nodes[i]?.parentId);
  if (!changed) return;
  clearTimeout(timer);
  timer = setTimeout(() => useSim.getState().run(), 150);
});
