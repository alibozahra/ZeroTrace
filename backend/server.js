'use strict';

// ============================================================
// ZEROTRACE SERVER — Express routes only
// ============================================================

process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';
process.on('warning', function(w) {
    if (w.message && w.message.includes('NODE_TLS_REJECT_UNAUTHORIZED')) return;
    console.warn(w.name + ':', w.message);
});

const express = require('express');
const cors    = require('cors');
const path    = require('path');
const fs      = require('fs');

const {
    SESSIONS_DIR, REPORTS_DIR, LOGS_DIR,
    loadSession, saveSession, createSession, updateSession, sessionPath
} = require('./sessions');

const { runAllRecon }          = require('./recon/runner');
const { analyzeVulnerabilities } = require('./analysis/analyzer');
const { generateExploit }      = require('./exploits/exploiter');
const {
    buildVulnReport, buildReport, buildExploitReport, parseVulnerabilitiesFromText,
    severityToImpact, severityToLikelihood
} = require('./reports/reporter');

const app  = express();
const PORT = 3000;

app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, '../frontend')));

// ============================================================
// POST /api/start-session
// ============================================================
app.post('/api/start-session', function(req, res) {
    const { target, scanType, sessionType } = req.body;
    if (!target) return res.status(400).json({ error: 'target required' });
    const session = createSession(target, scanType || 'quick', sessionType || 'vuln');
    res.json({ sessionId: session.sessionId });
});

// ============================================================
// POST /api/run-scan  (Step 1 — 7 recon tools)
// ============================================================
app.post('/api/run-scan', async function(req, res) {
    const sessionId = req.body.sessionId;
    if (!sessionId) return res.status(400).json({ error: 'sessionId required' });
    const session = loadSession(sessionId);
    if (!session) return res.status(404).json({ error: 'Session not found' });

    updateSession(sessionId, { status: 'scanning' });

    try {
        const { combined, raw, openPorts } = await runAllRecon(session.target, session.scanType, sessionId);
        const summary = `Reconnaissance complete.\n6 tools executed.\nOpen ports detected: ${openPorts}\n\nFull output saved to logs directory.`;
        updateSession(sessionId, {
            status:      'recon_complete',
            reconOutput: combined,
            reconRaw:    raw,
            nmapOutput:  raw.nmap
        });
        res.json({ nmapOutput: summary });
    } catch (err) {
        updateSession(sessionId, { status: 'failed' });
        res.status(500).json({ error: err.message });
    }
});

// ============================================================
// POST /api/run-analysis  (Step 2 — zerotrace-v2)
// ============================================================
app.post('/api/run-analysis', async function(req, res) {
    const sessionId = req.body.sessionId;
    const session   = loadSession(sessionId);
    if (!session) return res.status(404).json({ error: 'Session not found' });

    updateSession(sessionId, { status: 'analyzing' });

    try {
        const reconRaw = session.reconRaw || { nmap: session.reconOutput || session.nmapOutput || '' };
        const vulnerabilities = await analyzeVulnerabilities(reconRaw, session.target);
        updateSession(sessionId, { status: 'analysis_complete', vulnerabilities });

        // Save standalone JSON file
        let vulnFileName = null;
        try {
            const ts   = Date.now();
            const slug = (session.target || 'scan').replace(/[^a-zA-Z0-9._-]/g, '_').substring(0, 40);
            vulnFileName = 'vulns_' + slug + '_' + ts + '.json';
            const vulnFilePath = path.join(REPORTS_DIR, vulnFileName);
            fs.writeFileSync(vulnFilePath, JSON.stringify({ vulnerabilities }, null, 2), 'utf8');
            console.log('[ANALYSIS] Vulnerability export saved: ' + vulnFilePath);
        } catch (fe) {
            console.warn('[ANALYSIS] Failed to save vuln export file:', fe.message);
        }

        res.json({ vulnerabilities, vulnFile: vulnFileName });
    } catch (err) {
        updateSession(sessionId, { status: 'analysis_failed' });
        res.status(500).json({ error: err.message });
    }
});

// ============================================================
// POST /api/generate-exploits  (Step 4)
// ============================================================
app.post('/api/generate-exploits', async function(req, res) {
    const sessionId = req.body.sessionId;
    const session   = loadSession(sessionId);
    if (!session) return res.status(404).json({ error: 'Session not found' });

    updateSession(sessionId, { status: 'generating_exploits' });

    try {
        const vulnList = session.vulnerabilities || [];
        const exploits = [];
        console.log('\n════════════════════════════════════════');
        console.log('STEP 3 — EXPLOIT GENERATION (zerotrace-deepseek:latest)');
        console.log(`[EXPLOITS] Generating exploits for ${vulnList.length} vulnerabilities`);
        console.log('════════════════════════════════════════');
        for (let i = 0; i < vulnList.length; i++) {
            const exploit = await generateExploit(vulnList[i], i, vulnList.length);
            exploits.push(exploit);
        }
        updateSession(sessionId, { status: 'exploits_ready', exploits });
        res.json({ exploits });
    } catch (err) {
        updateSession(sessionId, { status: 'exploit_generation_failed' });
        res.status(500).json({ error: err.message });
    }
});

// ============================================================
// POST /api/generate-report  (Step 5)
// ============================================================
app.post('/api/generate-report', async function(req, res) {
    const sessionId = req.body.sessionId;
    const session   = loadSession(sessionId);
    if (!session) return res.status(404).json({ error: 'Session not found' });

    updateSession(sessionId, { status: 'generating_report' });

    try {
        const result = await buildReport(session);
        updateSession(sessionId, {
            status:             'completed',
            overallRisk:        result.overallRisk,
            reportMarkdownPath: result.mdFile,
            reportPdfPath:      result.pdfFile
        });
        res.json({ success: true, overallRisk: result.overallRisk });
    } catch (err) {
        console.error('[REPORT] Report generation failed:', err.message);
        updateSession(sessionId, { status: 'report_failed' });
        res.status(500).json({ error: err.message });
    }
});

// ============================================================
// POST /api/generate-vuln-report
// ============================================================
app.post('/api/generate-vuln-report', async function(req, res) {
    const { sessionId } = req.body;
    const session = loadSession(sessionId);
    if (!session) return res.status(404).json({ error: 'Session not found' });

    updateSession(sessionId, { status: 'generating_report' });
    try {
        const result = await buildVulnReport(session);
        updateSession(sessionId, {
            status:             'completed',
            overallRisk:        result.overallRisk,
            reportMarkdownPath: result.mdFile,
            reportPdfPath:      result.pdfFile
        });
        res.json({ success: true, overallRisk: result.overallRisk });
    } catch (err) {
        console.error('[VULN REPORT]', err.message);
        updateSession(sessionId, { status: 'report_failed' });
        res.status(500).json({ error: err.message });
    }
});

// ============================================================
// POST /api/create-exploit-session
// ============================================================
app.post('/api/create-exploit-session', async function(req, res) {
    const { vulnData, target } = req.body;
    if (!vulnData) return res.status(400).json({ error: 'vulnData required' });
    try {
        const vulnerabilities = await parseVulnerabilitiesFromText(vulnData);
        if (!vulnerabilities.length) {
            return res.status(400).json({ error: 'No vulnerabilities could be parsed from the provided data. Please provide JSON or a text report with vulnerability details.' });
        }
        const session = createSession(target || 'Manual Input', 'quick', 'exploit');
        updateSession(session.sessionId, {
            vulnerabilities,
            status:      'analysis_complete',
            reconOutput: 'Vulnerabilities provided manually.'
        });
        res.json({ sessionId: session.sessionId, vulnerabilities });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// ============================================================
// POST /api/generate-exploit-report
// ============================================================
app.post('/api/generate-exploit-report', async function(req, res) {
    const { sessionId } = req.body;
    const session = loadSession(sessionId);
    if (!session) return res.status(404).json({ error: 'Session not found' });

    updateSession(sessionId, { status: 'generating_report' });
    try {
        const result = await buildExploitReport(session);
        updateSession(sessionId, {
            status:             'completed',
            reportMarkdownPath: result.mdFile,
            reportPdfPath:      result.pdfFile
        });
        res.json({ success: true });
    } catch (err) {
        console.error('[EXPLOIT REPORT]', err.message);
        updateSession(sessionId, { status: 'report_failed' });
        res.status(500).json({ error: err.message });
    }
});

// ============================================================
// GET /api/sessions
// ============================================================
app.get('/api/sessions', function(req, res) {
    try {
        const files    = fs.readdirSync(SESSIONS_DIR).filter(function(f) { return f.endsWith('.json'); });
        const sessions = files.map(function(f) {
            try { return JSON.parse(fs.readFileSync(path.join(SESSIONS_DIR, f), 'utf8')); }
            catch (_) { return null; }
        }).filter(Boolean);
        res.json(sessions);
    } catch (_) { res.json([]); }
});

// GET /api/session/:id
app.get('/api/session/:id', function(req, res) {
    const session = loadSession(req.params.id);
    if (!session) return res.status(404).json({ error: 'Not found' });
    res.json(session);
});

// DELETE /api/session/:id
app.delete('/api/session/:id', function(req, res) {
    const session = loadSession(req.params.id);
    if (!session) return res.status(404).json({ error: 'Not found' });
    if (session.reportMarkdownPath && fs.existsSync(session.reportMarkdownPath)) fs.unlinkSync(session.reportMarkdownPath);
    if (session.reportPdfPath && fs.existsSync(session.reportPdfPath)) fs.unlinkSync(session.reportPdfPath);
    fs.unlinkSync(sessionPath(req.params.id));
    res.json({ success: true });
});

// GET /api/download-report/:id
app.get('/api/download-report/:id', function(req, res) {
    const session = loadSession(req.params.id);
    if (!session || !session.reportMarkdownPath) return res.status(404).json({ error: 'No report' });
    if (!fs.existsSync(session.reportMarkdownPath)) return res.status(404).json({ error: 'File not found' });
    res.download(session.reportMarkdownPath);
});

// GET /api/download-pdf/:id
app.get('/api/download-pdf/:id', function(req, res) {
    const session = loadSession(req.params.id);
    if (!session || !session.reportPdfPath) return res.status(404).json({ error: 'No PDF' });
    if (!fs.existsSync(session.reportPdfPath)) return res.status(404).json({ error: 'File not found' });
    res.download(session.reportPdfPath);
});

// GET /api/download-file/:filename
app.get('/api/download-file/:filename', function(req, res) {
    const filename = req.params.filename.replace(/[^a-zA-Z0-9._-]/g, '');
    if (!filename) return res.status(400).json({ error: 'Invalid filename' });
    const filePath = path.join(REPORTS_DIR, filename);
    if (!fs.existsSync(filePath)) return res.status(404).json({ error: 'File not found' });
    res.download(filePath);
});

// ============================================================
// GET /api/dashboards
// ============================================================
app.get('/api/dashboards', function(req, res) {
    try {
        const files = fs.readdirSync(SESSIONS_DIR).filter(function(f) { return f.endsWith('.json'); });
        const sessions = files.map(function(f) {
            try { return JSON.parse(fs.readFileSync(path.join(SESSIONS_DIR, f), 'utf8')); }
            catch (_) { return null; }
        }).filter(function(s) { return s && (s.sessionType === 'vuln' || !s.sessionType) && s.vulnerabilities && s.vulnerabilities.length > 0; });

        const targetMap = {};
        sessions.forEach(function(s) {
            const key = s.target || 'Unknown';
            if (!targetMap[key]) {
                targetMap[key] = {
                    target: key, sessionCount: 0, uniqueVulnMap: {},
                    severityCounts: { Critical: 0, High: 0, Medium: 0, Low: 0 },
                    latestDate: null, overallRisk: 'Low'
                };
            }
            const entry = targetMap[key];
            entry.sessionCount++;
            (s.vulnerabilities || []).forEach(function(v) {
                const vkey = (v.name || '').toLowerCase().replace(/\s+/g, ' ').trim();
                if (!entry.uniqueVulnMap[vkey]) {
                    entry.uniqueVulnMap[vkey] = v;
                    const sev = v.severity || 'Low';
                    if (entry.severityCounts[sev] !== undefined) entry.severityCounts[sev]++;
                }
            });
            if (!entry.latestDate || s.createdAt > entry.latestDate) entry.latestDate = s.createdAt;
            const severityOrder = ['Critical', 'High', 'Medium', 'Low'];
            if (s.overallRisk && severityOrder.indexOf(s.overallRisk) < severityOrder.indexOf(entry.overallRisk)) {
                entry.overallRisk = s.overallRisk;
            }
        });
        const result = Object.values(targetMap).map(function(entry) {
            return {
                target: entry.target, totalVulns: Object.keys(entry.uniqueVulnMap).length,
                totalScans: entry.sessionCount, severityCounts: entry.severityCounts,
                latestDate: entry.latestDate, overallRisk: entry.overallRisk
            };
        });
        res.json(result);
    } catch (err) {
        console.error('[DASHBOARDS]', err.message);
        res.json([]);
    }
});

// GET /api/dashboard/:target
app.get('/api/dashboard/:target', function(req, res) {
    const targetName = decodeURIComponent(req.params.target);
    try {
        const files = fs.readdirSync(SESSIONS_DIR).filter(function(f) { return f.endsWith('.json'); });
        const sessions = files.map(function(f) {
            try { return JSON.parse(fs.readFileSync(path.join(SESSIONS_DIR, f), 'utf8')); }
            catch (_) { return null; }
        }).filter(function(s) { return s && s.target === targetName && (s.sessionType === 'vuln' || !s.sessionType); });

        const allVulnsRaw = [];
        sessions.sort(function(a, b) { return (a.createdAt || 0) - (b.createdAt || 0); });
        sessions.forEach(function(s) {
            (s.vulnerabilities || []).forEach(function(v) {
                allVulnsRaw.push(Object.assign({}, v, { scanDate: s.createdAt, sessionId: s.sessionId }));
            });
        });
        const vulnMap = {};
        allVulnsRaw.forEach(function(v) {
            const key = (v.name || '').toLowerCase().replace(/\s+/g, ' ').trim();
            vulnMap[key] = v;
        });
        const allVulns = Object.values(vulnMap);

        const severityCounts   = { Critical: 0, High: 0, Medium: 0, Low: 0 };
        const impactCounts     = { 'Very High': 0, High: 0, Medium: 0, Low: 0 };
        const likelihoodCounts = { High: 0, 'Medium-High': 0, Medium: 0, Low: 0 };

        allVulns.forEach(function(v) {
            const sev = v.severity || 'Low';
            if (severityCounts[sev] !== undefined) severityCounts[sev]++;
            const impact = severityToImpact(sev);
            if (impactCounts[impact] !== undefined) impactCounts[impact]++;
            const likelihood = severityToLikelihood(sev);
            if (likelihoodCounts[likelihood] !== undefined) likelihoodCounts[likelihood]++;
        });

        res.json({
            target: targetName, totalScans: sessions.length, totalVulns: allVulns.length,
            severityCounts, impactCounts, likelihoodCounts, vulnerabilities: allVulns,
            sessions: sessions.map(function(s) {
                return {
                    sessionId: s.sessionId, createdAt: s.createdAt,
                    vulnCount: (s.vulnerabilities || []).length,
                    overallRisk: s.overallRisk, status: s.status
                };
            })
        });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// ============================================================
// START
// ============================================================
app.listen(PORT, '0.0.0.0', function() {
    const { networkInterfaces } = require('os');
    const nets = networkInterfaces();
    let localIp = 'unknown';
    for (const iface of Object.values(nets)) {
        for (const net of iface) {
            if (net.family === 'IPv4' && !net.internal) { localIp = net.address; break; }
        }
        if (localIp !== 'unknown') break;
    }
    console.log('ZeroTrace server running on:');
    console.log('  Local:   http://localhost:' + PORT);
    console.log('  Network: http://' + localIp + ':' + PORT);
});
