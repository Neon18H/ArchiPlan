import type { Rect } from '@xyflow/react';
import { toPng, toSvg } from 'html-to-image';

export function download(filename: string, content: string | Blob, mime = 'text/plain;charset=utf-8') {
  const blob = typeof content === 'string' ? new Blob([content], { type: mime }) : content;
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 2000);
}

export function downloadDataUrl(filename: string, dataUrl: string) {
  const a = document.createElement('a');
  a.href = dataUrl;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
}

const filter = (node: HTMLElement) => {
  const c = node?.classList;
  if (!c) return true;
  return !(c.contains('react-flow__minimap') || c.contains('react-flow__controls') || c.contains('react-flow__panel') || c.contains('react-flow__handle') || c.contains('react-flow__resize-control') || c.contains('no-export'));
};

/** Captura todo el diagrama (no solo lo visible) a PNG o SVG. */
export async function captureDiagram(bounds: Rect, format: 'png' | 'svg', scale = 2): Promise<string> {
  const el = document.querySelector('.react-flow__viewport') as HTMLElement | null;
  if (!el) throw new Error('No se encontró el lienzo');
  const pad = 40;
  const width = Math.ceil(bounds.width + pad * 2);
  const height = Math.ceil(bounds.height + pad * 2);
  const opts = {
    backgroundColor: '#ffffff',
    width,
    height,
    pixelRatio: format === 'png' ? scale : 1,
    filter,
    style: {
      width: `${width}px`,
      height: `${height}px`,
      transform: `translate(${pad - bounds.x}px, ${pad - bounds.y}px) scale(1)`,
    },
  };
  document.body.classList.add('exporting');
  try {
    return format === 'png' ? await toPng(el, opts) : await toSvg(el, opts);
  } finally {
    document.body.classList.remove('exporting');
  }
}

export async function diagramToPdf(dataUrl: string, title: string, subtitle: string) {
  const { jsPDF } = await import('jspdf');
  const img = new Image();
  img.src = dataUrl;
  await img.decode();
  const landscape = img.width >= img.height;
  const doc = new jsPDF({ orientation: landscape ? 'landscape' : 'portrait', unit: 'mm', format: 'a3' });
  const pw = doc.internal.pageSize.getWidth();
  const ph = doc.internal.pageSize.getHeight();
  const margin = 12;
  doc.setFont('helvetica', 'bold');
  doc.setFontSize(16);
  doc.text(title, margin, margin + 4);
  doc.setFont('helvetica', 'normal');
  doc.setFontSize(9);
  doc.setTextColor(100);
  doc.text(subtitle, margin, margin + 10);
  const top = margin + 16;
  const maxW = pw - margin * 2;
  const maxH = ph - top - margin;
  const ratio = Math.min(maxW / img.width, maxH / img.height);
  const w = img.width * ratio;
  const hgt = img.height * ratio;
  doc.addImage(dataUrl, 'PNG', margin + (maxW - w) / 2, top, w, hgt);
  return doc.output('blob');
}
