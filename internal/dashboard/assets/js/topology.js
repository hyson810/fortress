// internal/dashboard/assets/js/topology.js
const Topology = {
  render(canvasId) {
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

    ctx.clearRect(0, 0, w, h);

    // Background grid
    ctx.strokeStyle = 'rgba(255,255,255,0.03)';
    ctx.lineWidth = 1;
    for (let x = 0; x < w; x += 40) {
      ctx.beginPath(); ctx.moveTo(x, 0); ctx.lineTo(x, h); ctx.stroke();
    }
    for (let y = 0; y < h; y += 40) {
      ctx.beginPath(); ctx.moveTo(0, y); ctx.lineTo(w, y); ctx.stroke();
    }

    // Center node (protected network)
    ctx.beginPath();
    ctx.arc(w / 2, h / 2, 35, 0, Math.PI * 2);
    const grad = ctx.createRadialGradient(w/2, h/2, 5, w/2, h/2, 35);
    grad.addColorStop(0, 'rgba(0,255,136,0.4)');
    grad.addColorStop(1, 'rgba(0,255,136,0.05)');
    ctx.fillStyle = grad;
    ctx.fill();
    ctx.strokeStyle = '#00ff88';
    ctx.lineWidth = 2;
    ctx.stroke();

    ctx.fillStyle = '#fff';
    ctx.font = 'bold 12px monospace';
    ctx.textAlign = 'center';
    ctx.textBaseline = 'middle';
    ctx.fillText('NET', w/2, h/2);

    // Attacker nodes
    const attackers = [
      {x: w*0.12, y: h*0.12, ip: '10.0.0.88', score: 88.3},
      {x: w*0.85, y: h*0.15, ip: '192.168.1.50', score: 92.5},
      {x: w*0.08, y: h*0.78, ip: '172.16.0.99', score: 72.1},
      {x: w*0.82, y: h*0.82, ip: '203.0.113.4', score: 45.2},
      {x: w*0.50, y: h*0.05, ip: '45.33.22.11', score: 61.0},
    ];

    attackers.forEach(function(a) {
      // Connection lines with gradient
      ctx.beginPath();
      ctx.moveTo(w / 2, h / 2);
      ctx.lineTo(a.x, a.y);
      const alpha = Math.min(a.score / 100, 1);
      ctx.strokeStyle = 'rgba(255, 51, 85, ' + (alpha * 0.4) + ')';
      ctx.lineWidth = 1 + alpha * 3;
      ctx.stroke();

      // Animated dot moving along the line
      const t = ((Date.now() % 3000) / 3000);
      const dx = a.x - w/2, dy = a.y - h/2;
      const fx = w/2 + dx * t, fy = h/2 + dy * t;
      ctx.beginPath();
      ctx.arc(fx, fy, 3, 0, Math.PI * 2);
      ctx.fillStyle = '#ff3355';
      ctx.fill();

      // Attacker node circle
      ctx.beginPath();
      ctx.arc(a.x, a.y, 12 + alpha * 10, 0, Math.PI * 2);
      ctx.fillStyle = 'rgba(255, 51, 85, ' + (alpha * 0.7) + ')';
      ctx.fill();
      ctx.strokeStyle = 'rgba(255, 51, 85, ' + alpha + ')';
      ctx.lineWidth = 2;
      ctx.stroke();

      // IP label
      ctx.fillStyle = '#e8e8ed';
      ctx.font = '10px monospace';
      ctx.textAlign = 'center';
      ctx.textBaseline = 'top';
      ctx.fillText(a.ip, a.x, a.y + 24);

      // Score label
      ctx.fillStyle = '#ff3355';
      ctx.font = 'bold 11px monospace';
      ctx.textBaseline = 'bottom';
      ctx.fillText(a.score.toFixed(1), a.x, a.y - 14);
    });

    requestAnimationFrame(function() { Topology.render(canvasId); });
  }
};
