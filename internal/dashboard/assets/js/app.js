// internal/dashboard/assets/js/app.js
const App = {
  currentRoute: 'overview',

  init() {
    this.bindNav();
    this.connectSSE();
    this.route(window.location.pathname);
    window.addEventListener('popstate', () => this.route(window.location.pathname));
  },

  bindNav() {
    document.querySelectorAll('.nav-link').forEach(a => {
      a.addEventListener('click', e => {
        e.preventDefault();
        const path = a.getAttribute('data-route') || '/';
        window.history.pushState(null, '', path);
        this.route(path);
      });
    });
  },

  route(path) {
    document.querySelectorAll('.nav-link').forEach(a => a.classList.remove('active'));
    const link = document.querySelector(`.nav-link[data-route="${path}"]`);
    if (link) link.classList.add('active');
    this.currentRoute = path;
    this.render();
  },

  async fetchAPI(path) {
    try {
      const resp = await fetch(path);
      if (!resp.ok) throw new Error('HTTP ' + resp.status);
      return await resp.json();
    } catch (e) {
      console.error('API error:', e);
      return null;
    }
  },

  async render() {
    const main = document.getElementById('main-content');
    switch (this.currentRoute) {
      case '/': case '/overview':
        this.renderOverview(main); break;
      case '/threats':
        this.renderThreats(main); break;
      case '/timeline':
        this.renderTimeline(main); break;
      case '/correlation':
        this.renderCorrelation(main); break;
      case '/topology':
        this.renderTopology(main); break;
      case '/heatmap':
        this.renderHeatmap(main); break;
      case '/evidence':
        this.renderEvidence(main); break;
      default:
        main.innerHTML = '<div class="empty-state"><h3>Page not found</h3></div>';
    }
  },

  async renderOverview(container) {
    const stats = await this.fetchAPI('/api/stats') || {};
    container.innerHTML = `
      <div class="stat-grid">
        <div class="card"><div class="card-title">Packets Processed</div>
          <div class="card-value">${(stats.packets_processed || 0).toLocaleString()}</div></div>
        <div class="card"><div class="card-title">Active Threats</div>
          <div class="card-value">${stats.active_threats || 0}</div>
          <div class="card-change up">${stats.threats_detected || 0} detected today</div></div>
        <div class="card"><div class="card-title">Packets Dropped</div>
          <div class="card-value">${(stats.packets_dropped || 0).toLocaleString()}</div></div>
        <div class="card"><div class="card-title">Uptime</div>
          <div class="card-value">${Math.floor((stats.uptime_seconds || 0) / 3600)}h</div></div>
      </div>
      <div class="pipeline-section" id="pipeline-container">
        <div class="card-title" style="padding:0 0 8px 0">Pipeline Status</div>
      </div>
      <div class="card"><div class="card-title">Traffic History (1h)</div>
        <div class="canvas-container" style="height:200px">
          <canvas id="chart-traffic"></canvas>
        </div>
      </div>`;
    this.renderPipeline();
    setTimeout(() => Charts.traffic('chart-traffic'), 100);
  },

  async renderPipeline() {
    const stats = await this.fetchAPI('/api/stats') || {};
    const stages = stats.pipeline_status || [];
    const container = document.getElementById('pipeline-container');
    if (!container) return;
    container.innerHTML = '<div class="card-title" style="padding:0 0 8px 0">Pipeline Status</div>';
    container.innerHTML += stages.map(s => {
      const cls = s.status === 'critical' ? 'crit' : s.status === 'warning' ? 'warn' : 'ok';
      return '<div class="pipeline-bar">'
        + '<span class="pipeline-label">' + s.stage + '</span>'
        + '<div class="pipeline-track"><div class="pipeline-fill ' + cls + '" style="width:' + s.load_pct + '%"></div></div>'
        + '<span class="pipeline-pps">' + (s.pps || 0).toFixed(0) + '/s</span>'
        + '<span class="pipeline-status">' + (s.status === 'ok' ? '🟢' : s.status === 'warning' ? '🟡' : '🔴') + '</span>'
        + '</div>';
    }).join('');
    if (stages.length === 0) {
      container.innerHTML += '<div class="empty-state"><p style="padding:20px 0">No pipeline data available</p></div>';
    }
  },

  async renderThreats(container) {
    const threats = await this.fetchAPI('/api/threats?limit=100') || [];
    container.innerHTML = '<div class="card" style="margin-bottom:16px">'
      + '<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:12px">'
      + '<div class="card-title" style="margin:0">Active Threats (' + threats.length + ')</div>'
      + '<input type="text" id="threat-search" class="search-input" placeholder="Search IP...">'
      + '</div>'
      + '<table class="threat-table"><thead><tr>'
      + '<th>Severity</th><th>IP</th><th>Score</th><th>Scan</th><th>Flood</th><th>Anomaly</th><th>Intel</th><th>Status</th>'
      + '</tr></thead><tbody id="threat-tbody"></tbody></table></div>'
      + '<div id="threat-detail"></div>';

    const tbody = document.getElementById('threat-tbody');
    threats.forEach(t => {
      const level = (t.level || 'low').toLowerCase();
      const cls = level === 'critical' ? 'severity-critical' : level === 'high' ? 'severity-high' : 'severity-medium';
      tbody.innerHTML += '<tr class="' + cls + '" onclick="App.showThreatDetail(\'' + t.ip + '\')">'
        + '<td><span class="' + cls + '">● ' + level.toUpperCase() + '</span></td>'
        + '<td>' + t.ip + '</td>'
        + '<td>' + (t.total_score || 0).toFixed(1) + '</td>'
        + '<td>' + (t.scan_score || 0).toFixed(1) + '</td>'
        + '<td>' + (t.flood_score || 0).toFixed(1) + '</td>'
        + '<td>' + (t.anomaly_score || 0).toFixed(1) + '</td>'
        + '<td>' + (t.intel_score || 0).toFixed(1) + '</td>'
        + '<td>' + (t.banned ? '🔒' : '-') + '</td>'
        + '</tr>';
    });

    document.getElementById('threat-search').addEventListener('input', function(e) {
      const q = e.target.value.toLowerCase();
      tbody.querySelectorAll('tr').forEach(tr => {
        tr.style.display = tr.cells[1] && tr.cells[1].textContent.toLowerCase().includes(q) ? '' : 'none';
      });
    });
  },

  async showThreatDetail(ip) {
    const data = await this.fetchAPI('/api/threats/' + encodeURIComponent(ip)) || {};
    const container = document.getElementById('threat-detail');
    container.innerHTML = '<div class="card">'
      + '<div class="threat-detail-header">'
      + '<div><div class="card-title">Threat Detail</div>'
      + '<h3 style="font-family:var(--font-mono);color:var(--accent-red)">' + (data.ip || ip) + '</h3></div>'
      + '<div style="text-align:right"><div class="threat-score-large" style="color:' + ((data.score || 0) >= 80 ? 'var(--accent-red)' : (data.score || 0) >= 50 ? 'var(--accent-orange)' : 'var(--accent-yellow)') + '">' + (data.score || 0).toFixed(1) + '</div>'
      + '<div style="font-size:12px;color:var(--text-muted)">Score &middot; ' + (data.level || 'unknown') + '</div></div>'
      + '</div>'
      + '<div class="canvas-container" style="height:250px;margin-top:16px">'
      + '<canvas id="chart-radar"></canvas></div></div>';
    setTimeout(() => Charts.radar('chart-radar', data.score || 0, data.scan_score || 0, data.flood_score || 0, data.anomaly_score || 0), 100);
  },

  renderTimeline(container) {
    container.innerHTML = '<div class="card"><div class="card-title">Alert Timeline</div>'
      + '<p style="font-size:12px;color:var(--text-muted);margin-bottom:12px">Real-time security events</p>'
      + '<div class="timeline" id="timeline-container"></div></div>';
    this.refreshTimeline();
  },

  async refreshTimeline() {
    const alerts = await this.fetchAPI('/api/timeline?limit=200') || [];
    const tc = document.getElementById('timeline-container');
    if (!tc) return;
    tc.innerHTML = alerts.length === 0
      ? '<div class="empty-state"><h3>No alerts</h3><p>Waiting for security events...</p></div>'
      : alerts.map(function(a) {
          const sev = (a.severity || 0) >= 4 ? 'critical' : (a.severity || 0) >= 3 ? 'high' : (a.severity || 0) >= 2 ? 'medium' : 'info';
          const ts = new Date((a.ts || 0) * 1000).toLocaleTimeString();
          return '<div class="timeline-item ' + sev + '">'
            + '<span class="timeline-time">' + ts + '</span>'
            + '<div class="timeline-content"><strong>' + (a.source || 'unknown') + '</strong> ' + (a.message || '') + ''
            + '<div class="timeline-source">' + (a.ip ? 'IP: ' + a.ip : '') + (a.score ? ' Score: ' + a.score.toFixed(1) : '') + '</div>'
            + '</div></div>';
        }).join('');
  },

  renderCorrelation(container) {
    container.innerHTML = '<div class="empty-state"><h3>Correlation Analysis</h3>'
      + '<p>Cross-layer attack chain visualization coming soon</p></div>';
  },

  renderTopology(container) {
    container.innerHTML = '<div class="card"><div class="card-title">Network Topology</div>'
      + '<div class="canvas-container" style="height:500px"><canvas id="canvas-topology"></canvas></div></div>';
    setTimeout(function() { Topology.render('canvas-topology'); }, 100);
  },

  renderHeatmap(container) {
    container.innerHTML = '<div class="card"><div class="card-title">Port &times; IP Attack Heatmap</div>'
      + '<div class="canvas-container" style="height:400px"><canvas id="canvas-heatmap"></canvas></div></div>';
    setTimeout(function() { Charts.heatmap('canvas-heatmap'); }, 100);
  },

  renderEvidence(container) {
    container.innerHTML = '<div class="card"><div class="card-title">Evidence Chain</div>'
      + '<div style="display:flex;gap:8px;margin-bottom:16px">'
      + '<input type="text" id="evidence-ip" class="evidence-input" placeholder="Enter IP address...">'
      + '<button class="btn-primary" onclick="App.lookupEvidence()">Verify</button></div>'
      + '<div id="evidence-results"></div></div>';
  },

  async lookupEvidence() {
    const ip = document.getElementById('evidence-ip').value.trim();
    if (!ip) return;
    const data = await this.fetchAPI('/api/evidence/' + encodeURIComponent(ip)) || {};
    const container = document.getElementById('evidence-results');
    container.innerHTML = '<div class="verify-badge">'
      + '<span class="' + (data.chain_valid ? 'verify-valid' : 'verify-invalid') + '">'
      + (data.chain_valid ? '🟢 Chain Valid' : '🔴 Chain Broken') + '</span>'
      + '<span style="color:var(--text-muted);font-size:12px">' + ((data.items || []).length) + ' records</span></div>'
      + ((data.items || []).map(function(e) {
          return '<div class="pipeline-bar">'
            + '<span class="pipeline-label">' + new Date((e.ts || 0) * 1000).toLocaleTimeString() + '</span>'
            + '<span style="flex:1;font-size:12px">' + (e.summary || e.type || 'N/A') + '</span>'
            + '<span style="font-size:10px;color:var(--text-muted);font-family:var(--font-mono)">' + ((e.hash || '').slice(0, 16)) + '...</span>'
            + '</div>';
        }).join('') || '<div class="empty-state"><p>No evidence for this IP</p></div>');
  },

  connectSSE() {
    const es = new EventSource('/ws');
    es.onmessage = function(e) {
      try {
        const msg = JSON.parse(e.data);
        if (msg.type === 'pipeline_tick' && App.currentRoute === '/overview') {
          App.renderPipeline();
        }
        if (msg.type === 'alert_new' && App.currentRoute === '/timeline') {
          App.refreshTimeline();
        }
      } catch(e) { /* ignore parse errors */ }
    };
    es.onerror = function() { setTimeout(function() { App.connectSSE(); }, 3000); };
  }
};

document.addEventListener('DOMContentLoaded', function() { App.init(); });
