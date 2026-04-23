const API_URL = 'http://localhost:3000/api';
let currentSessionId = null;

// ============================================================
// HELPERS
// ============================================================

function escapeHtml(text) {
    const d = document.createElement('div');
    d.textContent = text;
    return d.innerHTML;
}

function severityBadge(sev) {
    const s = (sev || 'info').toLowerCase();
    return `<span class="badge badge-${s}">${escapeHtml(sev || 'info')}</span>`;
}

function riskBadge(risk) { return severityBadge(risk); }

// ============================================================
// VULNERABILITY ANALYSIS PAGE
// ============================================================

const VA_STAGES = ['recon', 'analysis', 'report', 'complete'];

function vaSetStage(active) {
    let reached = false;
    VA_STAGES.forEach(s => {
        const el = document.getElementById(`va-stage-${s}`);
        if (!el) return;
        if (s === active) {
            el.className = 'stage active'; reached = true;
        } else if (!reached) {
            el.querySelector('.stage-dot').textContent = '✓';
            el.className = 'stage completed';
        } else {
            el.className = 'stage';
        }
    });
}

function vaShowStep(id) {
    ['vaStepRecon','vaStepAnalysis','vaStepReport'].forEach(i => {
        const el = document.getElementById(i);
        if (el) el.style.display = 'none';
    });
    const el = document.getElementById(id);
    if (el) el.style.display = 'block';
}

function vaSetBanner(label, name, badgeText, done) {
    const lEl = document.getElementById('vaBannerLabel');
    const nEl = document.getElementById('vaBannerName');
    const bEl = document.getElementById('vaStatusBadge');
    const banner = document.getElementById('vaBanner');
    if (lEl) lEl.textContent = label;
    if (nEl) nEl.textContent = name;
    if (bEl) { bEl.textContent = badgeText; bEl.className = done ? 'badge badge-completed' : 'badge badge-scanning'; }
    if (banner) {
        banner.style.borderColor = done ? 'var(--success)' : 'var(--accent)';
        banner.querySelectorAll('.pulse-dot').forEach(d => {
            d.style.background  = done ? 'var(--success)' : 'var(--accent)';
            d.style.animation   = done ? 'none' : '';
            d.style.opacity     = done ? '1' : '';
            d.style.transform   = done ? 'scale(1)' : '';
        });
    }
}

async function startVulnAnalysis() {
    const target   = document.getElementById('vaTarget').value.trim();
    const scanType = document.getElementById('vaScanType').value;
    if (!target) { alert('Please enter a target URL or IP.'); return; }

    document.getElementById('vaConfigCard').style.display  = 'none';
    document.getElementById('vaSessionPanel').style.display = 'block';
    document.getElementById('vaTargetDisplay').textContent  = target;

    // Create session
    let sessionId;
    try {
        const r   = await fetch(`${API_URL}/start-session`, {
            method: 'POST', headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ target, scanType, sessionType: 'vuln' })
        });
        sessionId = (await r.json()).sessionId;
        currentSessionId = sessionId;
    } catch (err) {
        alert('Failed to create session: ' + err.message);
        document.getElementById('vaConfigCard').style.display  = 'block';
        document.getElementById('vaSessionPanel').style.display = 'none';
        return;
    }

    // ── Step 1: Recon ──────────────────────────────────────────
    vaSetStage('recon');
    vaSetBanner('Step 1 of 4', 'Reconnaissance — Running 6 tools…', 'Scanning', false);
    vaShowStep('vaStepRecon');
    document.getElementById('vaReconLoading').style.display = 'flex';
    document.getElementById('vaReconOutput').style.display  = 'none';

    let reconSummary = '';
    try {
        const r = await fetch(`${API_URL}/run-scan`, {
            method: 'POST', headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ sessionId })
        });
        reconSummary = (await r.json()).nmapOutput || 'Scan complete.';
    } catch (err) { reconSummary = 'Scan failed: ' + err.message; }

    document.getElementById('vaReconLoading').style.display = 'none';
    document.getElementById('vaReconOutput').style.display  = 'block';
    document.getElementById('vaReconContent').textContent   = reconSummary;

    // ── Step 2: Analysis ───────────────────────────────────────
    vaSetStage('analysis');
    vaSetBanner('Step 2 of 4', 'Vulnerability Analysis — zerotrace-v2:latest…', 'Analyzing', false);
    vaShowStep('vaStepAnalysis');
    document.getElementById('vaAnalysisLoading').style.display = 'flex';
    document.getElementById('vaAnalysisOutput').style.display  = 'none';

    let vulnerabilities = [];
    let vulnExportFile  = null;
    try {
        const r = await fetch(`${API_URL}/run-analysis`, {
            method: 'POST', headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ sessionId })
        });
        const data = await r.json();
        vulnerabilities = data.vulnerabilities || [];
        vulnExportFile  = data.vulnFile || null;
    } catch (err) { vulnerabilities = []; }

    // Show "Download Vulnerabilities JSON" button if a file was saved
    if (vulnExportFile) {
        const btn = document.getElementById('vaDownloadVulnsBtn');
        if (btn) {
            btn.style.display = '';
            btn.dataset.file  = vulnExportFile;
        }
    }

    document.getElementById('vaAnalysisLoading').style.display = 'none';
    document.getElementById('vaAnalysisOutput').style.display  = 'block';
    renderVulnCards(vulnerabilities, 'vaVulnCards');

    if (!vulnerabilities.length) {
        vaSetStage('complete');
        vaSetBanner('Complete', 'Pipeline Complete — No vulnerabilities found', 'Completed', true);
        vaShowStep('vaStepReport');
        document.getElementById('vaReportLoading').style.display = 'none';
        document.getElementById('vaReportOutput').style.display  = 'block';
        return;
    }

    // ── Step 3: Report ─────────────────────────────────────────
    vaSetStage('report');
    vaSetBanner('Step 3 of 4', 'Report Generation — mistral:7b-instruct-q8_0…', 'Writing report', false);
    vaShowStep('vaStepReport');
    document.getElementById('vaReportLoading').style.display = 'flex';
    document.getElementById('vaReportOutput').style.display  = 'none';

    let reportOk = false;
    try {
        const r = await fetch(`${API_URL}/generate-vuln-report`, {
            method: 'POST', headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ sessionId })
        });
        const data = await r.json();
        if (!r.ok) throw new Error(data.error || `HTTP ${r.status}`);
        reportOk = true;
    } catch (err) {
        console.error('[Report] Generation failed:', err.message);
    }

    document.getElementById('vaReportLoading').style.display = 'none';
    document.getElementById('vaReportOutput').style.display  = 'block';
    vaSetStage('complete');
    if (reportOk) {
        vaSetBanner('Step 4 of 4', 'Pipeline Complete — Report Ready', 'Completed', true);
    } else {
        vaSetBanner('Step 4 of 4', 'Pipeline Complete — Report generation failed, retrying with template…', 'Completed', true);
        // Retry once — server will use fallback template on second call
        try {
            await fetch(`${API_URL}/generate-vuln-report`, {
                method: 'POST', headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ sessionId })
            });
        } catch (_) {}
    }
}

function vaDownloadPdf() {
    if (currentSessionId) window.open(`${API_URL}/download-pdf/${currentSessionId}`, '_blank');
}
function vaDownloadMarkdown() {
    if (currentSessionId) window.open(`${API_URL}/download-report/${currentSessionId}`, '_blank');
}
function vaDownloadVulns() {
    const btn = document.getElementById('vaDownloadVulnsBtn');
    if (btn && btn.dataset.file) {
        window.open(`${API_URL}/download-file/${encodeURIComponent(btn.dataset.file)}`, '_blank');
    }
}

// ============================================================
// EXPLOIT GENERATION PAGE
// ============================================================

let egSessionId = null;

const EG_STAGES = ['parse', 'exploits', 'report', 'complete'];

function egSetStage(active) {
    let reached = false;
    EG_STAGES.forEach(s => {
        const el = document.getElementById(`eg-stage-${s}`);
        if (!el) return;
        if (s === active) {
            el.className = 'stage active'; reached = true;
        } else if (!reached) {
            el.querySelector('.stage-dot').textContent = '✓';
            el.className = 'stage completed';
        } else {
            el.className = 'stage';
        }
    });
}

function egShowStep(id) {
    ['egStepParse','egStepExploits','egStepReport'].forEach(i => {
        const el = document.getElementById(i);
        if (el) el.style.display = 'none';
    });
    const el = document.getElementById(id);
    if (el) el.style.display = 'block';
}

function egSetBanner(label, name, badgeText, done) {
    const lEl = document.getElementById('egBannerLabel');
    const nEl = document.getElementById('egBannerName');
    const bEl = document.getElementById('egStatusBadge');
    const banner = document.getElementById('egBanner');
    if (lEl) lEl.textContent = label;
    if (nEl) nEl.textContent = name;
    if (bEl) { bEl.textContent = badgeText; bEl.className = done ? 'badge badge-completed' : 'badge badge-scanning'; }
    if (banner) {
        banner.style.borderColor = done ? 'var(--success)' : 'var(--accent)';
        banner.querySelectorAll('.pulse-dot').forEach(d => {
            d.style.background = done ? 'var(--success)' : 'var(--accent)';
            d.style.animation  = done ? 'none' : '';
            d.style.opacity    = done ? '1' : '';
            d.style.transform  = done ? 'scale(1)' : '';
        });
    }
}

function egLoadFile(event) {
    const file = event.target.files[0];
    if (!file) return;
    const reader = new FileReader();
    reader.onload = e => {
        document.getElementById('egVulnText').value = e.target.result;
    };
    reader.readAsText(file);
}

async function startExploitGen() {
    const vulnData = document.getElementById('egVulnText').value.trim();
    const target   = document.getElementById('egTarget').value.trim();

    if (!vulnData) { alert('Please paste vulnerability data or upload a file.'); return; }

    document.getElementById('egConfigCard').style.display  = 'none';
    document.getElementById('egSessionPanel').style.display = 'block';

    // ── Step 1: Parse ─────────────────────────────────────────
    egSetStage('parse');
    egSetBanner('Step 1 of 4', 'Parsing vulnerabilities…', 'Parsing', false);
    egShowStep('egStepParse');
    document.getElementById('egParseLoading').style.display = 'flex';
    document.getElementById('egParseOutput').style.display  = 'none';

    let vulnerabilities = [];
    try {
        const r = await fetch(`${API_URL}/create-exploit-session`, {
            method: 'POST', headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ vulnData, target: target || 'Manual Input' })
        });
        const data = await r.json();
        if (!r.ok) { alert(data.error || 'Failed to parse vulnerabilities'); resetEgForm(); return; }
        egSessionId = data.sessionId;
        vulnerabilities = data.vulnerabilities || [];
    } catch (err) { alert('Failed: ' + err.message); resetEgForm(); return; }

    document.getElementById('egParseLoading').style.display = 'none';
    document.getElementById('egParseOutput').style.display  = 'block';
    renderVulnCards(vulnerabilities, 'egParsedVulns');

    // ── Step 2: Exploits ──────────────────────────────────────
    egSetStage('exploits');
    egSetBanner('Step 2 of 4', 'Exploit Generation — zerotrace-deepseek:latest…', 'Generating', false);
    egShowStep('egStepExploits');
    document.getElementById('egExploitsLoading').style.display = 'flex';
    document.getElementById('egExploitsOutput').style.display  = 'none';
    document.getElementById('egExploitsLoadingText').textContent =
        `Generating exploits for ${vulnerabilities.length} vulnerabilit${vulnerabilities.length === 1 ? 'y' : 'ies'}…`;

    let exploits = [];
    try {
        const r = await fetch(`${API_URL}/generate-exploits`, {
            method: 'POST', headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ sessionId: egSessionId })
        });
        exploits = (await r.json()).exploits || [];
    } catch (_) {}

    document.getElementById('egExploitsLoading').style.display = 'none';
    document.getElementById('egExploitsOutput').style.display  = 'block';
    renderExploitCards(exploits, 'egExploitCards');

    // ── Step 3: Report ────────────────────────────────────────
    egSetStage('report');
    egSetBanner('Step 3 of 4', 'Report Generation — mistral:7b-instruct-q8_0…', 'Writing report', false);
    egShowStep('egStepReport');
    document.getElementById('egReportLoading').style.display = 'flex';
    document.getElementById('egReportOutput').style.display  = 'none';

    let egReportOk = false;
    try {
        const r = await fetch(`${API_URL}/generate-exploit-report`, {
            method: 'POST', headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ sessionId: egSessionId })
        });
        const data = await r.json();
        if (!r.ok) throw new Error(data.error || `HTTP ${r.status}`);
        egReportOk = true;
    } catch (err) {
        console.error('[Exploit Report] Generation failed:', err.message);
    }

    document.getElementById('egReportLoading').style.display = 'none';
    document.getElementById('egReportOutput').style.display  = 'block';
    egSetStage('complete');
    if (egReportOk) {
        egSetBanner('Step 4 of 4', 'Pipeline Complete — Report Ready', 'Completed', true);
    } else {
        egSetBanner('Step 4 of 4', 'Pipeline Complete — Report generation failed, retrying with template…', 'Completed', true);
        try {
            await fetch(`${API_URL}/generate-exploit-report`, {
                method: 'POST', headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ sessionId: egSessionId })
            });
        } catch (_) {}
    }
}

function resetEgForm() {
    document.getElementById('egConfigCard').style.display  = 'block';
    document.getElementById('egSessionPanel').style.display = 'none';
}

function egDownloadPdf() {
    if (egSessionId) window.open(`${API_URL}/download-pdf/${egSessionId}`, '_blank');
}
function egDownloadMarkdown() {
    if (egSessionId) window.open(`${API_URL}/download-report/${egSessionId}`, '_blank');
}

// ============================================================
// SHARED CARD RENDERERS
// ============================================================

function renderVulnCards(vulns, containerId) {
    const container = document.getElementById(containerId);
    if (!container) return;
    if (!vulns.length) {
        container.innerHTML = '<p style="color:var(--text-muted);font-size:0.875rem;">No vulnerabilities identified.</p>';
        return;
    }
    container.innerHTML = vulns.map(v => `
        <div class="vuln-card">
            <div class="vuln-card-header">
                <span class="vuln-name">${escapeHtml(v.name || 'Unknown')}</span>
                ${severityBadge(v.severity || 'info')}
            </div>
            <div class="vuln-meta">
                ${v.cve ? `<span>CVE: ${escapeHtml(v.cve)}</span>` : ''}
                ${v.tool_detected_by ? `<span>Detected by: ${escapeHtml(v.tool_detected_by)}</span>` : ''}
                ${v.affected_component ? `<span>Component: ${escapeHtml(v.affected_component)}</span>` : ''}
            </div>
            ${v.description ? `<p class="vuln-description">${escapeHtml(v.description)}</p>` : ''}
        </div>
    `).join('');
}

function renderExploitCards(exploits, containerId) {
    const container = document.getElementById(containerId);
    if (!container) return;
    if (!exploits.length) {
        container.innerHTML = '<p style="color:var(--text-muted);font-size:0.875rem;margin-bottom:1rem;">No exploits generated.</p>';
        return;
    }
    container.innerHTML = exploits.map((e, i) => {
        const code  = e.exploit_code || e.code || '';
        const steps = e.exploitation_steps || e.steps || [];
        const stepsHtml = Array.isArray(steps) && steps.length
            ? `<div style="margin-top:0.75rem;"><span style="font-size:0.78rem;color:var(--text-muted);font-weight:600;">STEPS</span>
               <ol style="margin-left:1.25rem;margin-top:0.4rem;">${steps.map(s => `<li style="font-size:0.82rem;color:var(--text-muted);margin-bottom:3px;">${escapeHtml(s)}</li>`).join('')}</ol></div>` : '';
        return `
        <div class="vuln-card">
            <div class="vuln-card-header">
                <span class="vuln-name">Exploit ${i+1}: ${escapeHtml(e.name || 'Unnamed')}</span>
                ${e.mitre_technique || e.mitre ? `<span style="font-family:'JetBrains Mono',monospace;font-size:0.75rem;color:var(--text-muted);">${escapeHtml(e.mitre_technique || e.mitre)}</span>` : ''}
            </div>
            ${stepsHtml}
            ${code ? `
            <div class="terminal" style="margin-top:0.75rem;">
                <div class="terminal-header">
                    <div class="terminal-dot red"></div><div class="terminal-dot yellow"></div><div class="terminal-dot green"></div>
                    <span class="terminal-title">exploit code</span>
                </div>
                <div class="terminal-body" style="max-height:220px;">${escapeHtml(code)}</div>
            </div>` : ''}
        </div>`;
    }).join('');
}

// ============================================================
// DASHBOARDS PAGE
// ============================================================

function showDashboardList() {
    document.getElementById('dashboardsView').style.display  = 'block';
    document.getElementById('targetDashboard').style.display = 'none';
}

async function loadDashboards() {
    const loadEl  = document.getElementById('dashLoading');
    const gridEl  = document.getElementById('dashGrid');
    const emptyEl = document.getElementById('dashEmpty');
    if (!loadEl) return;

    loadEl.style.display = 'flex';
    gridEl.style.display = 'none';
    emptyEl.style.display = 'none';

    let targets = [];
    try {
        const r = await fetch(`${API_URL}/dashboards`);
        targets = await r.json();
    } catch (_) {}

    loadEl.style.display = 'none';

    if (!targets.length) { emptyEl.style.display = 'block'; return; }

    gridEl.innerHTML = '';
    targets.forEach(t => {
        const date  = t.latestDate ? new Date(t.latestDate).toLocaleDateString('en-GB', { day:'numeric', month:'short', year:'numeric' }) : '—';
        const sc    = t.severityCounts || {};
        const risk  = t.overallRisk || 'Unknown';
        const card  = document.createElement('div');
        card.className = 'target-card';
        card.onclick = () => loadTargetDashboard(t.target);
        card.innerHTML = `
            <div class="target-card-header">
                <span class="target-name">${escapeHtml(t.target)}</span>
                ${riskBadge(risk)}
            </div>
            <div class="target-card-stats">
                <div class="target-stat"><span class="target-stat-num">${t.totalVulns}</span><span class="target-stat-label">Vulns</span></div>
                <div class="target-stat"><span class="target-stat-num" style="color:#e74c3c;">${sc.Critical||0}</span><span class="target-stat-label">Critical</span></div>
                <div class="target-stat"><span class="target-stat-num" style="color:#e67e22;">${sc.High||0}</span><span class="target-stat-label">High</span></div>
                <div class="target-stat"><span class="target-stat-num" style="color:#f39c12;">${sc.Medium||0}</span><span class="target-stat-label">Medium</span></div>
                <div class="target-stat"><span class="target-stat-num" style="color:#27ae60;">${sc.Low||0}</span><span class="target-stat-label">Low</span></div>
            </div>
            <div class="target-card-footer">
                <span style="font-size:0.78rem;color:var(--text-muted);">${t.sessionCount} scan${t.sessionCount !== 1 ? 's' : ''} &nbsp;·&nbsp; Last: ${date}</span>
                <span style="font-size:0.78rem;color:var(--accent);font-weight:600;">View Dashboard →</span>
            </div>`;
        gridEl.appendChild(card);
    });
    gridEl.style.display = 'grid';
}

async function loadTargetDashboard(target) {
    document.getElementById('dashboardsView').style.display  = 'none';
    document.getElementById('targetDashboard').style.display = 'block';

    document.getElementById('dbTargetTitle').textContent = target;
    document.getElementById('dbTargetMeta').textContent  = 'Loading dashboard…';

    let data = {};
    try {
        const r = await fetch(`${API_URL}/dashboard/${encodeURIComponent(target)}`);
        data = await r.json();
    } catch (_) { data = {}; }

    const sc = data.severityCounts   || {};
    const ic = data.impactCounts     || {};
    const lc = data.likelihoodCounts || {};

    document.getElementById('dbTargetMeta').textContent  = `${data.totalScans || 0} scan(s) performed · ${data.totalVulns || 0} total vulnerabilities`;
    document.getElementById('dbTotalVulns').textContent  = data.totalVulns || 0;
    document.getElementById('dbTotalScans').textContent  = data.totalScans || 0;
    document.getElementById('dbCritCount').textContent   = sc.Critical || 0;
    document.getElementById('dbHighCount').textContent   = sc.High     || 0;
    document.getElementById('dbMedCount').textContent    = sc.Medium   || 0;
    document.getElementById('dbLowCount').textContent    = sc.Low      || 0;

    const total = data.totalVulns || 1;

    // Severity chart
    renderBarChart('dbSeverityChart', [
        { label: 'Critical', value: sc.Critical||0, color: '#e74c3c', total },
        { label: 'High',     value: sc.High    ||0, color: '#e67e22', total },
        { label: 'Medium',   value: sc.Medium  ||0, color: '#f39c12', total },
        { label: 'Low',      value: sc.Low     ||0, color: '#27ae60', total },
    ]);

    // Impact chart
    renderBarChart('dbImpactChart', [
        { label: 'Very High', value: ic['Very High']||0, color: '#e74c3c', total },
        { label: 'High',      value: ic.High      ||0, color: '#e67e22', total },
        { label: 'Medium',    value: ic.Medium    ||0, color: '#f39c12', total },
        { label: 'Low',       value: ic.Low       ||0, color: '#27ae60', total },
    ]);

    // Likelihood chart
    renderBarChart('dbLikelihoodChart', [
        { label: 'High',        value: lc.High        ||0, color: '#e74c3c', total },
        { label: 'Medium-High', value: lc['Medium-High']||0, color: '#e67e22', total },
        { label: 'Medium',      value: lc.Medium      ||0, color: '#f39c12', total },
        { label: 'Low',         value: lc.Low         ||0, color: '#27ae60', total },
    ]);

    // Vulnerability table
    const vulns = data.vulnerabilities || [];
    const tableEl = document.getElementById('dbVulnTable');
    if (vulns.length) {
        tableEl.innerHTML = `
            <div style="overflow-x:auto;">
            <table style="width:100%;border-collapse:collapse;font-size:0.83rem;">
                <thead>
                    <tr style="border-bottom:1px solid var(--border);color:var(--text-muted);">
                        <th style="text-align:left;padding:8px 10px;font-weight:600;">#</th>
                        <th style="text-align:left;padding:8px 10px;font-weight:600;">Vulnerability</th>
                        <th style="text-align:left;padding:8px 10px;font-weight:600;">Severity</th>
                        <th style="text-align:left;padding:8px 10px;font-weight:600;">CVE</th>
                        <th style="text-align:left;padding:8px 10px;font-weight:600;">Component</th>
                        <th style="text-align:left;padding:8px 10px;font-weight:600;">Impact</th>
                        <th style="text-align:left;padding:8px 10px;font-weight:600;">Likelihood</th>
                        <th style="text-align:left;padding:8px 10px;font-weight:600;">Detected By</th>
                    </tr>
                </thead>
                <tbody>
                    ${vulns.map((v, i) => `
                    <tr style="border-bottom:1px solid var(--border);">
                        <td style="padding:8px 10px;color:var(--text-dim);">${i+1}</td>
                        <td style="padding:8px 10px;font-weight:500;">${escapeHtml(v.name||'Unknown')}</td>
                        <td style="padding:8px 10px;">${severityBadge(v.severity)}</td>
                        <td style="padding:8px 10px;font-family:'JetBrains Mono',monospace;font-size:0.75rem;color:var(--text-muted);">${escapeHtml(v.cve||'N/A')}</td>
                        <td style="padding:8px 10px;color:var(--text-muted);">${escapeHtml(v.affected_component||'—')}</td>
                        <td style="padding:8px 10px;color:var(--text-muted);">${escapeHtml(impactFromSeverity(v.severity))}</td>
                        <td style="padding:8px 10px;color:var(--text-muted);">${escapeHtml(likelihoodFromSeverity(v.severity))}</td>
                        <td style="padding:8px 10px;color:var(--text-muted);">${escapeHtml(v.tool_detected_by||'—')}</td>
                    </tr>`).join('')}
                </tbody>
            </table></div>`;
    } else {
        tableEl.innerHTML = '<p style="color:var(--text-muted);font-size:0.85rem;">No vulnerabilities recorded.</p>';
    }

    // Scan history
    const sessions = data.sessions || [];
    const histEl   = document.getElementById('dbScanHistory');
    if (sessions.length) {
        histEl.innerHTML = sessions.map(s => {
            const d   = new Date(s.createdAt).toLocaleString();
            const cls = s.status === 'completed' ? 'badge-completed' : 'badge-scanning';
            return `<div style="display:flex;justify-content:space-between;align-items:center;padding:10px 0;border-bottom:1px solid var(--border);font-size:0.83rem;">
                <span style="color:var(--text-muted);">${d}</span>
                <span>${s.vulnCount} vuln${s.vulnCount !== 1 ? 's' : ''}</span>
                ${riskBadge(s.overallRisk || 'Unknown')}
                <span class="badge ${cls}">${s.status}</span>
            </div>`;
        }).join('');
    } else {
        histEl.innerHTML = '<p style="color:var(--text-muted);font-size:0.85rem;">No scan history.</p>';
    }
}

function impactFromSeverity(sev) {
    return ({ Critical: 'Very High', High: 'High', Medium: 'Medium', Low: 'Low' })[sev] || '—';
}
function likelihoodFromSeverity(sev) {
    return ({ Critical: 'High', High: 'Medium-High', Medium: 'Medium', Low: 'Low' })[sev] || '—';
}

function renderBarChart(containerId, items) {
    const el = document.getElementById(containerId);
    if (!el) return;
    const maxVal = Math.max(...items.map(i => i.value), 1);
    el.innerHTML = items.map(item => `
        <div class="db-bar-row">
            <span class="db-bar-label">${escapeHtml(item.label)}</span>
            <div class="db-bar-track">
                <div class="db-bar-fill" style="width:${(item.value / maxVal * 100).toFixed(1)}%;background:${item.color};"></div>
            </div>
            <span class="db-bar-value">${item.value}</span>
        </div>
    `).join('');
}

// ============================================================
// LIBRARY PAGE
// ============================================================

let activePanelSessionId = null;

async function loadLibrary() {
    const loadEl  = document.getElementById('libraryLoading');
    const colsEl  = document.getElementById('libraryColumns');
    const emptyEl = document.getElementById('libraryEmpty');
    if (!loadEl) return;

    loadEl.style.display = 'flex';
    if (colsEl)  colsEl.style.display  = 'none';
    if (emptyEl) emptyEl.style.display = 'none';

    let sessions = [];
    try {
        const r = await fetch(`${API_URL}/sessions`);
        sessions = await r.json();
    } catch (_) { sessions = []; }

    loadEl.style.display = 'none';

    if (!sessions.length) { if (emptyEl) emptyEl.style.display = 'block'; return; }

    // Split by session type
    const vulnSessions    = sessions.filter(s => !s.sessionType || s.sessionType === 'vuln').reverse();
    const exploitSessions = sessions.filter(s => s.sessionType === 'exploit').reverse();

    const vulnGrid    = document.getElementById('vulnGrid');
    const exploitGrid = document.getElementById('exploitGrid');
    const vulnEmpty   = document.getElementById('vulnEmpty');
    const exploitEmpty= document.getElementById('exploitEmpty');
    const vulnCount   = document.getElementById('vulnCount');
    const exploitCount= document.getElementById('exploitCount');

    if (vulnCount)    vulnCount.textContent    = vulnSessions.length;
    if (exploitCount) exploitCount.textContent = exploitSessions.length;

    if (vulnSessions.length && vulnGrid) {
        vulnGrid.innerHTML = '';
        vulnSessions.forEach(s => vulnGrid.appendChild(buildScanCard(s)));
        if (vulnEmpty) vulnEmpty.style.display = 'none';
    } else {
        if (vulnEmpty) vulnEmpty.style.display = 'block';
    }

    if (exploitSessions.length && exploitGrid) {
        exploitGrid.innerHTML = '';
        exploitSessions.forEach(s => exploitGrid.appendChild(buildScanCard(s)));
        if (exploitEmpty) exploitEmpty.style.display = 'none';
    } else {
        if (exploitEmpty) exploitEmpty.style.display = 'block';
    }

    if (!vulnSessions.length && !exploitSessions.length) {
        if (emptyEl) emptyEl.style.display = 'block';
        return;
    }

    if (colsEl) colsEl.style.display = 'flex';
}

function buildScanCard(s) {
    const date = new Date(s.createdAt).toLocaleDateString('en-GB', {
        day: 'numeric', month: 'short', year: 'numeric', hour: '2-digit', minute: '2-digit'
    });
    const vulnCount  = (s.vulnerabilities || []).length;
    const risk       = s.overallRisk || 'Unknown';
    const statusCls  = s.status === 'completed' ? 'badge-completed' : s.status === 'failed' ? 'badge-critical' : 'badge-scanning';

    const card = document.createElement('div');
    card.className = 'scan-card';
    card.onclick = () => openPanel(s.sessionId);
    card.innerHTML = `
        <div class="scan-card-header">
            <span class="scan-target">${escapeHtml(s.target || 'Unknown')}</span>
            ${riskBadge(risk)}
        </div>
        <div class="scan-card-meta">
            <span>📅 ${date}</span>
            <span>🔍 ${vulnCount} vulnerabilit${vulnCount === 1 ? 'y' : 'ies'}</span>
            <span><span class="badge ${statusCls}">${s.status}</span></span>
        </div>
        <div class="scan-card-footer">
            ${s.reportPdfPath ? `<button class="btn btn-sm btn-primary" onclick="event.stopPropagation(); libDownloadPdf('${s.sessionId}')">PDF</button>` : ''}
            ${s.reportMarkdownPath ? `<button class="btn btn-sm" onclick="event.stopPropagation(); libDownloadMd('${s.sessionId}')">MD</button>` : ''}
            <button class="btn btn-sm" onclick="event.stopPropagation(); deleteSession('${s.sessionId}')" style="margin-left:auto;color:#e74c3c;border-color:#c0392b;">Delete</button>
        </div>`;
    return card;
}

async function openPanel(sessionId) {
    activePanelSessionId = sessionId;
    let session = {};
    try {
        const r = await fetch(`${API_URL}/session/${sessionId}`);
        session = await r.json();
    } catch (_) {}

    document.getElementById('panelTitle').textContent = session.target || 'Session Details';
    document.getElementById('panelTarget').textContent = session.target || '—';
    const typeLabel = session.sessionType === 'exploit' ? 'Exploit Generation' : 'Vulnerability Analysis';
    const typeEl = document.getElementById('panelType');
    if (typeEl) typeEl.textContent = typeLabel;
    document.getElementById('panelDate').textContent = session.createdAt ? new Date(session.createdAt).toLocaleString() : '—';
    document.getElementById('panelSessionId').textContent = session.sessionId || '—';
    document.getElementById('panelStatus').innerHTML = `<span class="badge ${session.status === 'completed' ? 'badge-completed' : 'badge-scanning'}">${session.status || '—'}</span>`;
    document.getElementById('panelScanType').textContent = session.scanType || '—';

    const vulns = session.vulnerabilities || [];
    document.getElementById('panelVulnCount').textContent = vulns.length;

    const risk = session.overallRisk || 'Unknown';
    document.getElementById('panelRisk').innerHTML = riskBadge(risk);

    const recon = session.reconOutput || session.nmapOutput || 'No recon data available';
    document.getElementById('panelReconPreview').textContent =
        recon.substring(0, 1200) + (recon.length > 1200 ? '\n… (truncated)' : '');

    const vulnList = document.getElementById('panelVulnList');
    if (vulns.length) {
        vulnList.innerHTML = vulns.map(v => `
            <div style="display:flex;justify-content:space-between;align-items:center;padding:6px 0;border-bottom:1px solid var(--border);font-size:0.83rem;">
                <span>${escapeHtml(v.name || 'Unknown')}</span>
                ${severityBadge(v.severity)}
            </div>`).join('');
    } else {
        vulnList.innerHTML = '<p style="color:var(--text-muted);font-size:0.83rem;">No vulnerabilities recorded.</p>';
    }

    document.getElementById('panelPdfBtn').style.display = session.reportPdfPath ? 'inline-flex' : 'none';
    document.getElementById('panelMdBtn').style.display  = session.reportMarkdownPath ? 'inline-flex' : 'none';

    document.getElementById('panelOverlay').classList.add('open');
    document.getElementById('sidePanel').classList.add('open');
    document.body.style.overflow = 'hidden';
}

function closePanel() {
    document.getElementById('panelOverlay').classList.remove('open');
    document.getElementById('sidePanel').classList.remove('open');
    document.body.style.overflow = '';
}

function panelDownloadPdf() {
    if (activePanelSessionId) window.open(`${API_URL}/download-pdf/${activePanelSessionId}`, '_blank');
}
function panelDownloadMarkdown() {
    if (activePanelSessionId) window.open(`${API_URL}/download-report/${activePanelSessionId}`, '_blank');
}
function libDownloadPdf(sessionId) {
    window.open(`${API_URL}/download-pdf/${sessionId}`, '_blank');
}
function libDownloadMd(sessionId) {
    window.open(`${API_URL}/download-report/${sessionId}`, '_blank');
}

async function deleteSession(sessionId) {
    if (!confirm('Delete this session and its report? This cannot be undone.')) return;
    try { await fetch(`${API_URL}/session/${sessionId}`, { method: 'DELETE' }); } catch (_) {}
    loadLibrary();
}

// ============================================================
// INIT
// ============================================================

document.addEventListener('DOMContentLoaded', () => {
    const path = window.location.pathname;
    if (path.includes('library'))    loadLibrary();
    if (path.includes('dashboards')) loadDashboards();
});
