import { create } from 'zustand';

/** Estado de interfaz del modelo de amenazas (no se guarda en el proyecto). */
export const useThreatsUi = create<{ overlay: boolean; setOverlay: (v: boolean) => void }>((set) => ({
  overlay: false,
  setOverlay: (v) => set({ overlay: v }),
}));
