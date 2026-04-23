'use strict';

// ============================================================
// SESSION HELPERS — file-based session store
// ============================================================

const path = require('path');
const fs   = require('fs');
const { v4: uuidv4 } = require('uuid');

const SESSIONS_DIR = path.join(__dirname, '../sessions');
const REPORTS_DIR  = path.join(__dirname, '../reports');
const LOGS_DIR     = path.join(__dirname, '../logs');

[SESSIONS_DIR, REPORTS_DIR, LOGS_DIR].forEach(function(d) {
    if (!fs.existsSync(d)) fs.mkdirSync(d, { recursive: true });
});

function sessionPath(sessionId) {
    return path.join(SESSIONS_DIR, `${sessionId}.json`);
}

function loadSession(sessionId) {
    const p = sessionPath(sessionId);
    if (!fs.existsSync(p)) return null;
    return JSON.parse(fs.readFileSync(p, 'utf8'));
}

function saveSession(session) {
    fs.writeFileSync(sessionPath(session.sessionId), JSON.stringify(session, null, 2));
}

function createSession(target, scanType, sessionType) {
    const session = {
        sessionId:          uuidv4(),
        target,
        scanType,
        sessionType:        sessionType || 'vuln',
        createdAt:          new Date().toISOString(),
        status:             'initialized',
        reconOutput:        null,
        nmapOutput:         null,
        vulnerabilities:    [],
        exploits:           [],
        overallRisk:        null,
        reportMarkdownPath: null,
        reportPdfPath:      null
    };
    saveSession(session);
    return session;
}

function updateSession(sessionId, updates) {
    const s = loadSession(sessionId);
    if (!s) throw new Error('Session not found: ' + sessionId);
    Object.assign(s, updates);
    saveSession(s);
    return s;
}

module.exports = {
    SESSIONS_DIR, REPORTS_DIR, LOGS_DIR,
    sessionPath, loadSession, saveSession, createSession, updateSession
};
