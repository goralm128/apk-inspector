'use strict';

function getTimestamp() {
    return new Date().toISOString();
}

function classifyData(data) {
    if (!data || data === '[binary or unreadable]') return 'binary';

    const trimmed = data.trim();
    if (/^(GET|POST|PUT|DELETE|CONNECT|OPTIONS|HEAD)\s/i.test(trimmed)) return 'http';
    if ((trimmed.startsWith('{') || trimmed.startsWith('[')) && (trimmed.endsWith('}') || trimmed.endsWith(']'))) {
        try { JSON.parse(trimmed); return 'json'; } catch {}
    }
    if (/^[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+$/.test(trimmed)) return 'jwt';
    if (/[\w\-]{20,}/.test(trimmed) && /key|token|auth/i.test(trimmed)) return 'api_key';
    if (/^[\x20-\x7E\r\n\t]+$/.test(trimmed)) return 'text';
    return 'binary';
}

function classifyRisk(classification) {
    switch (classification) {
        case 'jwt':
        case 'api_key': return 'high';
        case 'http':
        case 'json':
        case 'text': return 'moderate';
        default: return 'low';
    }
}

function normalizeEvent(event) {
    event.timestamp = getTimestamp();
    event.classification = classifyData(event.data);
    event.risk_level = classifyRisk(event.classification);
    event.category = event.category || 'unknown';
    event.source = event.source || 'frida';
    event.tags = event.tags || [];

    if (event.classification === 'jwt') event.tags.push('token', 'auth');
    if (event.classification === 'api_key') event.tags.push('sensitive');
    if (event.classification === 'http') event.tags.push('web', 'plaintext');

    return event;
}

function log(event) {
    send(normalizeEvent(event));
}
