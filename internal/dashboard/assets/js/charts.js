// internal/dashboard/assets/js/charts.js
const Charts = {
  traffic(canvasId) {
    const canvas = document.getElementById(canvasId);
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    const rect = canvas.parentElement.getBoundingClientRect();
    canvas.width = rect.width * (window.devicePixelRatio || 1);
    canvas.height = rect.height * (window.devicePixelRatio || 1);
    canvas.style.width = rect.width + 'px';
    canvas.style.height = rect.height + 'px';
    ctx.scale(window.devicePixelRatio || 1, window.devicePixelRatio || 1);

    const w = rect.width, h = rect.height;
    const data = Array.from({length: 60}, function() { return Math.random() * h * 0.6 + h * 0.1; });

    ctx.clearRect(0, 0, w, h);

    // Grid lines
    ctx.strokeStyle = '#222233';
    ctx.lineWidth = 1;
    for (let y = 0; y < h; y += h / 4) {
      ctx.beginPath(); ctx.moveTo(0, y); ctx.lineTo(w, y); ctx.stroke();
    }

    // Fill
    ctx.beginPath();
    ctx.moveTo(0, h);
    data.forEach(function(v, i) { ctx.lineTo(i * w / data.length, h - v); });
    ctx.lineTo(w, h);
    ctx.closePath();
    ctx.fillStyle = 'rgba(0, 255, 136, 0.08)';
    ctx.fill();

    // Line
    ctx.beginPath();
    data.forEach(function(v, i) {
      const x = i * w / data.length;
      const y = h - v;
      i === 0 ? ctx.moveTo(x, y) : ctx.lineTo(x, y);
    });
    ctx.strokeStyle = '#00ff88';
    ctx.lineWidth = 2;
    ctx.stroke();
  },

  radar(canvasId, total, scan, flood, anomaly) {
    const canvas = document.getElementById(canvasId);
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    const rect = canvas.parentElement.getBoundingClientRect();
    canvas.width = rect.width * (window.devicePixelRatio || 1);
    canvas.height = rect.height * (window.devicePixelRatio || 1);
    canvas.style.width = rect.width + 'px';
    canvas.style.height = rect.height + 'px';
    ctx.scale(window.devicePixelRatio || 1, window.devicePixelRatio || 1);

    const w = rect.width, h = rect.height;
    const cx = w / 2, cy = h / 2, r = Math.min(w, h) / 2 - 30;
    const labels = ['Total', 'Scan', 'Flood', 'Anomaly', 'Intel'];
    const values = [total, scan, flood, anomaly, 0].map(function(v) { return Math.min(v || 0, 100) / 100; });

    ctx.clearRect(0, 0, w, h);

    // Grid rings
    for (let ring = 1; ring <= 5; ring++) {
      ctx.beginPath();
      for (let i = 0; i < labels.length; i++) {
        const angle = (Math.PI * 2 * i / labels.length) - Math.PI / 2;
        const x = cx + Math.cos(angle) * r * ring / 5;
        const y = cy + Math.sin(angle) * r * ring / 5;
        i === 0 ? ctx.moveTo(x, y) : ctx.lineTo(x, y);
      }
      ctx.closePath();
      ctx.strokeStyle = 'rgba(255,255,255,0.05)';
      ctx.stroke();
    }

    // Axis lines
    for (let i = 0; i < labels.length; i++) {
      const angle = (Math.PI * 2 * i / labels.length) - Math.PI / 2;
      ctx.beginPath(); ctx.moveTo(cx, cy); ctx.lineTo(cx + Math.cos(angle) * r, cy + Math.sin(angle) * r);
      ctx.strokeStyle = 'rgba(255,255,255,0.08)';
      ctx.stroke();
    }

    // Data polygon
    ctx.beginPath();
    for (let i = 0; i < labels.length; i++) {
      const angle = (Math.PI * 2 * i / labels.length) - Math.PI / 2;
      const x = cx + Math.cos(angle) * r * values[i];
      const y = cy + Math.sin(angle) * r * values[i];
      i === 0 ? ctx.moveTo(x, y) : ctx.lineTo(x, y);
    }
    ctx.closePath();
    ctx.fillStyle = 'rgba(0, 255, 136, 0.15)';
    ctx.fill();
    ctx.strokeStyle = '#00ff88';
    ctx.lineWidth = 2;
    ctx.stroke();

    // Data points
    for (let i = 0; i < labels.length; i++) {
      const angle = (Math.PI * 2 * i / labels.length) - Math.PI / 2;
      const x = cx + Math.cos(angle) * r * values[i];
      const y = cy + Math.sin(angle) * r * values[i];
      ctx.beginPath(); ctx.arc(x, y, 4, 0, Math.PI * 2);
      ctx.fillStyle = '#00ff88';
      ctx.fill();
    }

    // Labels
    ctx.fillStyle = '#888899';
    ctx.font = '12px monospace';
    ctx.textAlign = 'center';
    ctx.textBaseline = 'middle';
    for (let i = 0; i < labels.length; i++) {
      const angle = (Math.PI * 2 * i / labels.length) - Math.PI / 2;
      const x = cx + Math.cos(angle) * (r + 20);
      const y = cy + Math.sin(angle) * (r + 20);
      ctx.fillText(labels[i], x, y);
    }
  },

  heatmap(canvasId) {
    const canvas = document.getElementById(canvasId);
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    const rect = canvas.parentElement.getBoundingClientRect();
    canvas.width = rect.width * (window.devicePixelRatio || 1);
    canvas.height = rect.height * (window.devicePixelRatio || 1);
    canvas.style.width = rect.width + 'px';
    canvas.style.height = rect.height + 'px';
    ctx.scale(window.devicePixelRatio || 1, window.devicePixelRatio || 1);

    const w = rect.width, h = rect.height;
    const cols = 16, rows = 10;
    const cw = w / cols, ch = h / rows;

    ctx.clearRect(0, 0, w, h);

    // Axis labels
    ctx.fillStyle = '#555566';
    ctx.font = '10px monospace';
    ctx.textAlign = 'right';
    ctx.textBaseline = 'middle';
    for (let r = 0; r < rows; r++) {
      ctx.fillText((r * 25).toString(), 25, r * ch + ch / 2 + 24);
    }
    ctx.textAlign = 'center';
    ctx.textBaseline = 'top';
    for (let c = 0; c < cols; c++) {
      ctx.fillText((c * 1000 + 1).toString(), c * cw + cw / 2 + 25, 8);
    }

    // Cells
    for (let r = 0; r < rows; r++) {
      for (let c = 0; c < cols; c++) {
        const intensity = 0.1 + Math.random() * 0.6;
        const green = Math.round(255 * intensity);
        ctx.fillStyle = 'rgba(0, ' + green + ', ' + Math.round(136 * intensity) + ', ' + (0.2 + intensity * 0.5) + ')';
        ctx.fillRect(c * cw + 26, r * ch + 24, cw - 2, ch - 2);
      }
    }
  }
};
