// Lazy Mermaid loader (CDN ES module, loaded on first use) themed to match the app.
const CDN = 'https://cdn.jsdelivr.net/npm/mermaid@11/dist/mermaid.esm.min.mjs';
let loading = null;
let seq = 0;

export function loadMermaid() {
  if (!loading) {
    loading = import(CDN).then((m) => {
      const mermaid = m.default;
      mermaid.initialize({
        startOnLoad: false,
        securityLevel: 'strict',
        theme: 'base',
        fontFamily: 'Inter, system-ui, -apple-system, Segoe UI, sans-serif',
        themeVariables: {
          darkMode: true,
          background: '#0b1020',
          fontFamily: 'Inter, system-ui, -apple-system, Segoe UI, sans-serif',
          fontSize: '13px',
          primaryColor: '#1a1840',
          primaryTextColor: '#e7eaf3',
          primaryBorderColor: '#8b5cf6',
          secondaryColor: '#0e2530',
          secondaryTextColor: '#e7eaf3',
          secondaryBorderColor: '#22d3ee',
          tertiaryColor: '#111627',
          tertiaryTextColor: '#e7eaf3',
          tertiaryBorderColor: '#3b4256',
          lineColor: '#22d3ee',
          textColor: '#e7eaf3',
          mainBkg: '#1a1840',
          nodeBorder: '#8b5cf6',
          clusterBkg: 'rgba(244, 63, 94, 0.05)',
          clusterBorder: '#f43f5e',
          titleColor: '#b4bbcd',
          edgeLabelBackground: '#0b1020',
        },
        flowchart: { curve: 'basis', padding: 12 },
      });
      return mermaid;
    }).catch((e) => { loading = null; throw e; });
  }
  return loading;
}

/** Render Mermaid source to an SVG string. Throws when Mermaid cannot be loaded or the source is invalid. */
export async function renderMermaid(src) {
  const mermaid = await loadMermaid();
  const id = `mmd-${Date.now().toString(36)}-${seq++}`;
  try {
    const { svg } = await mermaid.render(id, src);
    return svg;
  } finally {
    document.getElementById(`d${id}`)?.remove();
    document.getElementById(id)?.remove();
  }
}
