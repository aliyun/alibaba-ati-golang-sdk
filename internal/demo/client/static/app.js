let eventSource = null;
let chatSource = null;

window.addEventListener('DOMContentLoaded', () => {
    initClientIdentities();
    initServerPolicy();
    linkAnim.init();
});

function initClientIdentities() {
    fetch('/api/client-identities')
        .then(r => r.json())
        .then(identities => {
            const select = document.getElementById('clientHost');
            select.innerHTML = '';
            identities.forEach((id, i) => {
                const opt = document.createElement('option');
                opt.value = id.host;
                opt.textContent = id.host;
                if (i === 0) opt.selected = true;
                select.appendChild(opt);
            });
        })
        .catch(() => {});
}

function initServerPolicy() {
    const proxyUrl = document.getElementById('agentHost').value;
    fetch(`/api/proxy-status?agentHost=${encodeURIComponent(proxyUrl)}`)
        .then(r => r.json())
        .then(data => {
            if (data.serverPolicy) {
                document.getElementById('serverPolicy').value = data.serverPolicy;
            }
        })
        .catch(() => {});
}

function updateServerPolicy() {
    const proxyUrl = document.getElementById('agentHost').value;
    const newPolicy = document.getElementById('serverPolicy').value;
    fetch(`/api/server-policy?agentHost=${encodeURIComponent(proxyUrl)}`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ policy: newPolicy })
    })
    .then(r => r.json())
    .then(data => {
        if (data.status !== 'ok') {
            alert('更新服务端策略失败：' + (data.message || '未知错误'));
        }
    })
    .catch(() => {
        alert('无法连接到 Proxy 更新策略');
    });
}

// --- Connect: real mTLS verification drives the constellation animation ---

function connect() {
    const agentHost = document.getElementById('agentHost').value;
    const clientHost = document.getElementById('clientHost').value;
    const serverVersion = document.getElementById('serverVersion').value;
    const policy = document.getElementById('clientPolicy').value;
    const serverPolicy = document.getElementById('serverPolicy').value;

    document.getElementById('connectBtn').disabled = true;
    const banner = document.getElementById('verify-banner');
    banner.classList.remove('show');
    banner.classList.add('hidden');
    banner.innerHTML = '';
    linkAnim.reset();

    let url = `/api/connect/stream?agentHost=${encodeURIComponent(agentHost)}&policy=${policy}`;
    url += `&clientHost=${encodeURIComponent(clientHost)}`;
    url += `&serverPolicy=${encodeURIComponent(serverPolicy)}`;
    if (serverVersion) {
        url += `&serverVersion=${encodeURIComponent(serverVersion)}`;
    }
    eventSource = new EventSource(url);

    eventSource.onmessage = (e) => {
        const data = JSON.parse(e.data);
        if (data.step === 'connected') {
            onConnected(data);
        } else {
            linkAnim.onStep(data);
        }
    };

    eventSource.onerror = () => {
        document.getElementById('connectBtn').disabled = false;
        if (eventSource) eventSource.close();
    };
}

function onConnected(data) {
    document.getElementById('chat-panel').classList.remove('disabled');
    document.getElementById('disconnectBtn').disabled = false;
    const details = data.details || {};
    const serverPolicy = document.getElementById('serverPolicy').value;
    document.getElementById('policy-summary').textContent = `client agent：${details.policy} | server agent：${serverPolicy}`;
    document.getElementById('target-agent').textContent = `目标：${details.targetAgent}`;
    const clientHost = document.getElementById('clientHost').value;
    document.getElementById('conn-status').textContent = `已连接 (${clientHost} → ${details.targetAgent})`;

    const banner = document.getElementById('verify-banner');
    banner.innerHTML =
        '<div class="vb-title">✅ SDK 双向身份认证成功</div>' +
        `<div class="vb-sub">Client Agent <code>${escapeHtml(clientHost)}</code> ⇄ Server Agent <code>${escapeHtml(details.targetAgent || '')}</code> · 已建立 mTLS 加密隧道（认证等级：${escapeHtml(details.policy || '')}）</div>`;
    banner.classList.remove('hidden');
    banner.classList.add('show');

    linkAnim.markConnected();
    if (eventSource) eventSource.close();
}

function disconnect() {
    const agentHost = document.getElementById('agentHost').value;
    fetch(`/api/disconnect?agentHost=${encodeURIComponent(agentHost)}`, { method: 'POST' })
        .then(() => {
            document.getElementById('chat-panel').classList.add('disabled');
            document.getElementById('connectBtn').disabled = false;
            document.getElementById('disconnectBtn').disabled = true;
            document.getElementById('conn-status').textContent = '未连接';
            document.getElementById('policy-summary').textContent = '';
            document.getElementById('target-agent').textContent = '';
            const banner = document.getElementById('verify-banner');
            banner.classList.remove('show');
            banner.classList.add('hidden');
            banner.innerHTML = '';
            linkAnim.idle();
        });
}

// --- Constellation animation ---
// Each verification step is an interaction between a specific initiator and a
// specific counterparty (Agent 发现 → 阿里云, 凭证验证 → 透明日志, mTLS → Agent B,
// DANE → DNS). Every step draws a labeled beam to the party it talked to.

const NODE_DEFS = {
    A:     { name: 'Agent A', sub: 'Client', color: '#818cf8', px: 0.14, py: 0.66 },
    B:     { name: 'Agent B', sub: 'Server', color: '#fbbf24', px: 0.86, py: 0.66 },
    cloud: { name: '阿里云',   sub: 'Agent 发现服务', color: '#38bdf8', px: 0.28, py: 0.20 },
    tl:    { name: 'CNNIC',    sub: '透明日志', color: '#a78bfa', px: 0.50, py: 0.13 },
    dns:   { name: 'DNS',      sub: 'DANE / TLSA', color: '#34d399', px: 0.72, py: 0.20 },
};

// parent step id -> {from, to, label of what is being verified}
const STEP_MAP = {
    A1: { from: 'A', to: 'cloud', label: 'Agent 发现·查询注册信息' },
    A2: { from: 'A', to: 'tl',    label: '凭证验证·签名+透明日志收录' },
    A3: { from: 'A', to: 'B',     label: 'mTLS 双向证书握手' },
    A4: { from: 'A', to: 'dns',   label: 'DANE·TLSA 记录校验' },
    B2: { from: 'B', to: 'tl',    label: '服务端验证 Client 凭证' },
    B3: { from: 'B', to: 'dns',   label: '服务端 DANE 校验 Client' },
    // B1 is the server side of the same mTLS handshake as A3 — skipped to avoid a duplicate line.
};

const linkAnim = {
    canvas: null, ctx: null, w: 0, h: 0, dpr: 1,
    nodes: {},
    bgStars: [],
    interactions: {},   // stepId -> {from,to,label,status}
    lines: [],          // completed: {stepId}
    queue: [],          // pending beams: {stepId,from,to}
    active: null,       // {stepId,from,to,t}
    state: 'idle',      // idle | running | connected | failed
    pendingConnected: false,
    lastSpawn: 0,
    lastLabel: '',
    running: false,

    init() {
        this.canvas = document.getElementById('link-canvas');
        if (!this.canvas) return;
        this.ctx = this.canvas.getContext('2d');
        window.addEventListener('resize', () => this.layout());
        this.layout();
        this.idle();
        this.loop();
    },

    layout() {
        if (!this.canvas) return;
        const rect = this.canvas.getBoundingClientRect();
        this.dpr = window.devicePixelRatio || 1;
        this.w = rect.width || 800;
        this.h = rect.height || 380;
        this.canvas.width = this.w * this.dpr;
        this.canvas.height = this.h * this.dpr;
        this.ctx.setTransform(this.dpr, 0, 0, this.dpr, 0, 0);
        const prev = this.nodes || {};
        this.nodes = {};
        for (const [k, d] of Object.entries(NODE_DEFS)) {
            const old = prev[k] || {};
            this.nodes[k] = {
                ...d, x: d.px * this.w, y: d.py * this.h,
                visible: old.visible || false,
                appearAt: old.appearAt || 0,
            };
        }
        this.makeStars();
    },

    // Initially only Agent A and the 阿里云 discovery service exist; Agent B is
    // revealed only after discovery finds it, and CNNIC/DNS light up per step.
    setInitialVisibility() {
        for (const [k, n] of Object.entries(this.nodes)) {
            n.visible = (k === 'A' || k === 'cloud');
            n.appearAt = 0;
        }
    },

    revealNode(key) {
        const n = this.nodes[key];
        if (!n || n.visible) return;
        n.visible = true;
        n.appearAt = performance.now();
    },

    makeStars() {
        this.bgStars = [];
        const palette = ['#60a5fa', '#818cf8', '#38bdf8', '#a78bfa', '#34d399'];
        for (let i = 0; i < 80; i++) {
            this.bgStars.push({
                x: Math.random() * this.w,
                y: Math.random() * this.h,
                r: Math.random() * 1.8 + 0.6,
                tw: Math.random() * Math.PI * 2,
                sp: Math.random() * 0.04 + 0.008,
                color: palette[(Math.random() * palette.length) | 0],
            });
        }
    },

    idle() {
        this.interactions = {};
        this.lines = [];
        this.queue = [];
        this.active = null;
        this.state = 'idle';
        this.pendingConnected = false;
        this.lastLabel = '';
        this.setInitialVisibility();
        this.setStatus('等待建立连接…');
    },

    reset() {
        this.layout();
        this.interactions = {};
        this.lines = [];
        this.queue = [];
        this.active = null;
        this.state = 'running';
        this.pendingConnected = false;
        this.lastLabel = '';
        this.setInitialVisibility();
        this.setStatus('建连中…');
    },

    setStatus(text) {
        const el = document.getElementById('link-status');
        if (!el) return;
        el.textContent = text;
        el.className = this.state === 'connected' ? 'success' : this.state === 'failed' ? 'failed' : '';
    },

    onStep(data) {
        if (!data || !data.step) return;
        const step = data.step;
        const isParent = step.length === 2 && (step[0] === 'A' || step[0] === 'B');
        if (!isParent) return;
        const def = STEP_MAP[step];
        if (!def) return;

        const existing = this.interactions[step];
        if (!existing) {
            this.interactions[step] = { from: def.from, to: def.to, label: def.label, status: data.status };
            // The initiator is already on screen; reveal the counterparty it talks to.
            this.revealNode(def.to);
            this.queue.push({ stepId: step, from: def.from, to: def.to });
            this.lastLabel = def.label;
        } else {
            existing.status = data.status;
        }
        // Agent B is discovered through 阿里云 — it only appears once discovery succeeds.
        if (step === 'A1' && data.status === 'success') {
            this.revealNode('B');
        }
        if (data.status === 'failed') {
            this.state = 'failed';
        }
    },

    markConnected() {
        this.pendingConnected = true;
        if (!this.active && this.queue.length === 0) this.finishConnected();
    },

    finishConnected() {
        if (this.state !== 'failed') this.state = 'connected';
    },

    ctrlPoint(p, q, curve) {
        const dx = q.x - p.x, dy = q.y - p.y;
        const len = Math.hypot(dx, dy) || 1;
        const nx = -dy / len, ny = dx / len;
        return { x: (p.x + q.x) / 2 + nx * curve, y: (p.y + q.y) / 2 + ny * curve };
    },

    bez(p, c, q, t) {
        const mt = 1 - t;
        return {
            x: mt * mt * p.x + 2 * mt * t * c.x + t * t * q.x,
            y: mt * mt * p.y + 2 * mt * t * c.y + t * t * q.y,
        };
    },

    statusColor(status) {
        if (status === 'failed') return '#f87171';
        if (status === 'success') return '#4ade80';
        return '#60a5fa';
    },

    nodeStatus(key) {
        let s = 'idle';
        for (const it of Object.values(this.interactions)) {
            if (it.from === key || it.to === key) {
                if (it.status === 'failed') return 'failed';
                if (it.status === 'success') s = 'success';
                else if (s === 'idle') s = 'running';
            }
        }
        return s;
    },

    drawLine(from, to, curve, color, alpha, label) {
        const ctx = this.ctx;
        const p = this.nodes[from], q = this.nodes[to];
        if (!p || !q || !p.visible || !q.visible) return;
        const c = this.ctrlPoint(p, q, curve);
        ctx.save();
        ctx.globalAlpha = alpha;
        ctx.strokeStyle = color;
        ctx.lineWidth = 2.8;
        ctx.shadowBlur = 14;
        ctx.shadowColor = color;
        ctx.beginPath();
        ctx.moveTo(p.x, p.y);
        ctx.quadraticCurveTo(c.x, c.y, q.x, q.y);
        ctx.stroke();
        ctx.restore();
        if (label) {
            const mid = this.bez(p, c, q, 0.5);
            this.drawLabel(mid.x, mid.y, label, color);
        }
    },

    drawLabel(x, y, text, color) {
        const ctx = this.ctx;
        ctx.save();
        ctx.font = '600 12px "PingFang SC", system-ui, sans-serif';
        const tw = ctx.measureText(text).width;
        const pad = 8, h = 20, w = tw + pad * 2;
        const rx = x - w / 2, ry = y - h / 2;
        ctx.fillStyle = 'rgba(255, 255, 255, 0.94)';
        ctx.strokeStyle = color;
        ctx.lineWidth = 1.4;
        ctx.beginPath();
        const r = 5;
        ctx.moveTo(rx + r, ry);
        ctx.arcTo(rx + w, ry, rx + w, ry + h, r);
        ctx.arcTo(rx + w, ry + h, rx, ry + h, r);
        ctx.arcTo(rx, ry + h, rx, ry, r);
        ctx.arcTo(rx, ry, rx + w, ry, r);
        ctx.closePath();
        ctx.fill();
        ctx.stroke();
        ctx.fillStyle = '#1e293b';
        ctx.textAlign = 'center';
        ctx.textBaseline = 'middle';
        ctx.fillText(text, x, y + 0.5);
        ctx.restore();
    },

    drawNode(key, ts) {
        const ctx = this.ctx;
        const n = this.nodes[key];
        if (!n || !n.visible) return;

        // Appear animation (scale + fade) when a node is first revealed.
        const prog = n.appearAt ? Math.min((ts - n.appearAt) / 480, 1) : 1;
        const ease = 1 - Math.pow(1 - prog, 3);

        const st = this.nodeStatus(key);
        const connected = this.state === 'connected';
        let color = n.color;
        if (st === 'failed') color = '#f87171';
        else if ((key === 'A' || key === 'B') && connected) color = '#4ade80';
        const glow = (st === 'idle' ? 16 : 24) * (0.5 + 0.5 * ease);
        const core = 5 * (0.4 + 0.6 * ease);

        // Spawn ring for the just-discovered node.
        if (prog < 1) {
            ctx.save();
            ctx.globalAlpha = (1 - prog) * 0.8;
            ctx.strokeStyle = color;
            ctx.lineWidth = 2;
            ctx.beginPath();
            ctx.arc(n.x, n.y, 10 + 40 * prog, 0, Math.PI * 2);
            ctx.stroke();
            ctx.restore();
        }

        const grd = ctx.createRadialGradient(n.x, n.y, 0, n.x, n.y, glow);
        grd.addColorStop(0, color);
        grd.addColorStop(1, 'rgba(0,0,0,0)');
        ctx.save();
        ctx.globalAlpha = (st === 'idle' ? 0.6 : 0.95) * ease;
        ctx.fillStyle = grd;
        ctx.beginPath();
        ctx.arc(n.x, n.y, glow, 0, Math.PI * 2);
        ctx.fill();
        ctx.restore();

        ctx.save();
        ctx.globalAlpha = ease;
        ctx.fillStyle = color;
        ctx.shadowBlur = 14;
        ctx.shadowColor = color;
        ctx.beginPath();
        ctx.arc(n.x, n.y, core, 0, Math.PI * 2);
        ctx.fill();
        ctx.restore();

        ctx.save();
        ctx.globalAlpha = ease;
        ctx.textAlign = 'center';
        ctx.fillStyle = '#0f172a';
        ctx.font = '800 16px "PingFang SC", system-ui, sans-serif';
        ctx.shadowBlur = 6;
        ctx.shadowColor = 'rgba(255,255,255,0.9)';
        ctx.fillText(n.name, n.x, n.y - 24 - 10);
        ctx.fillStyle = '#475569';
        ctx.font = '600 12px "PingFang SC", system-ui, sans-serif';
        ctx.fillText(n.sub, n.x, n.y - 24 + 6);
        ctx.restore();
    },

    loop() {
        if (this.running) return;
        this.running = true;
        const step = (ts) => { this.frame(ts); requestAnimationFrame(step); };
        requestAnimationFrame(step);
    },

    frame(ts) {
        const ctx = this.ctx;
        if (!ctx) return;
        ctx.clearRect(0, 0, this.w, this.h);

        // twinkling background stars
        for (const s of this.bgStars) {
            s.tw += s.sp;
            ctx.save();
            ctx.globalAlpha = 0.45 + 0.5 * (0.5 + 0.5 * Math.sin(s.tw));
            ctx.fillStyle = s.color;
            ctx.shadowBlur = 6;
            ctx.shadowColor = s.color;
            ctx.beginPath();
            ctx.arc(s.x, s.y, s.r, 0, Math.PI * 2);
            ctx.fill();
            ctx.restore();
        }

        const CURVE = 26;

        // completed labeled lines
        for (const ln of this.lines) {
            const it = this.interactions[ln.stepId];
            if (!it) continue;
            const color = this.statusColor(it.status);
            const pulse = it.status === 'success' ? 0.6 + 0.2 * Math.sin(ts / 400) : 0.6;
            this.drawLine(it.from, it.to, CURVE, color, pulse, it.label);
        }

        // spawn queued beam sequentially
        if (!this.active && this.queue.length > 0 && ts - this.lastSpawn > 220) {
            this.active = Object.assign({ t: 0 }, this.queue.shift());
            this.lastSpawn = ts;
            const it = this.interactions[this.active.stepId];
            if (it) { this.lastLabel = it.label; }
        }

        // animate active beam
        if (this.active) {
            const bm = this.active;
            const p = this.nodes[bm.from], q = this.nodes[bm.to];
            const c = this.ctrlPoint(p, q, CURVE);
            // faint guide line while beam travels
            this.drawLine(bm.from, bm.to, CURVE, '#3b82f6', 0.25, null);
            bm.t += 0.022;
            for (let k = 0; k < 7; k++) {
                const tt = bm.t - k * 0.035;
                if (tt < 0 || tt > 1) continue;
                const pt = this.bez(p, c, q, tt);
                ctx.save();
                ctx.globalAlpha = (1 - k / 7) * 0.95;
                ctx.fillStyle = '#2563eb';
                ctx.shadowBlur = 12;
                ctx.shadowColor = '#3b82f6';
                ctx.beginPath();
                ctx.arc(pt.x, pt.y, 3.4 - k * 0.35, 0, Math.PI * 2);
                ctx.fill();
                ctx.restore();
            }
            if (bm.t >= 1) {
                this.lines.push({ stepId: bm.stepId });
                this.active = null;
                if (this.pendingConnected && this.queue.length === 0) this.finishConnected();
            }
        }

        // nodes on top
        for (const key of Object.keys(this.nodes)) this.drawNode(key, ts);

        // status line
        if (this.state === 'running') {
            this.setStatus(this.lastLabel ? '建连中 · ' + this.lastLabel : '建连中…');
        } else if (this.state === 'connected') {
            this.setStatus('✅ 双向认证成功');
        } else if (this.state === 'failed') {
            this.setStatus('❌ 认证失败 · ' + (this.lastLabel || ''));
        }
    },
};

// --- Chat: streamed agentA <-> agentB orchestration ---

function sendMessage() {
    const input = document.getElementById('messageInput');
    const message = input.value.trim();
    if (!message) return;
    const city = (document.getElementById('cityInput').value || '北京').trim();

    addChatMessage('我', message);
    input.value = '';

    if (chatSource) { chatSource.close(); chatSource = null; }

    const thinking = addPlaceholder('Agent A 正在与 Agent B 协作…');

    let url = `/api/chat/stream?message=${encodeURIComponent(message)}&city=${encodeURIComponent(city)}`;
    chatSource = new EventSource(url);

    chatSource.onmessage = (e) => {
        const ev = JSON.parse(e.data);
        if (thinking && thinking.parentNode) thinking.remove();
        if (ev.type === 'turn') {
            addTurnBubble(ev.from, ev.to, ev.text);
        } else if (ev.type === 'summary') {
            addChatMessage('Agent A', ev.text, 'summary');
            chatSource.close();
            chatSource = null;
        } else if (ev.type === 'error') {
            addChatMessage('Agent A', '⚠️ ' + ev.text, 'summary');
            chatSource.close();
            chatSource = null;
        }
    };

    chatSource.onerror = () => {
        if (thinking && thinking.parentNode) thinking.remove();
        if (chatSource) { chatSource.close(); chatSource = null; }
    };

    input.focus();
}

function addPlaceholder(text) {
    const history = document.getElementById('chat-history');
    const msg = document.createElement('div');
    msg.className = 'chat-msg turn-ab';
    msg.innerHTML = `<div class="turn-label">⏳</div>${escapeHtml(text)}`;
    history.appendChild(msg);
    history.scrollTop = history.scrollHeight;
    return msg;
}

function addTurnBubble(from, to, text) {
    const history = document.getElementById('chat-history');
    const msg = document.createElement('div');
    const ab = from === 'A';
    msg.className = `chat-msg ${ab ? 'turn-ab' : 'turn-ba'}`;
    const label = ab ? 'Agent A → Agent B' : 'Agent B → Agent A';
    msg.innerHTML = `<div class="turn-label">${label}</div>${renderMarkdown(text)}`;
    history.appendChild(msg);
    history.scrollTop = history.scrollHeight;
}

function addChatMessage(sender, text, variant) {
    const history = document.getElementById('chat-history');
    const msg = document.createElement('div');
    let cssRole;
    if (sender === '我') cssRole = 'you';
    else if (variant === 'summary') cssRole = 'summary';
    else cssRole = 'turn-ba';
    msg.className = `chat-msg ${cssRole}`;
    if (sender === '我') {
        msg.innerHTML = `<strong>我：</strong> ${escapeHtml(text)}`;
    } else if (variant === 'summary') {
        msg.innerHTML = `<div class="turn-label">${escapeHtml(sender)} · 给用户的总结</div>${renderMarkdown(text)}`;
    } else {
        msg.innerHTML = `<strong>${escapeHtml(sender)}：</strong> ${renderMarkdown(text)}`;
    }
    history.appendChild(msg);
    history.scrollTop = history.scrollHeight;
}

function renderMarkdown(text) {
    if (typeof marked !== 'undefined') {
        const raw = marked.parse(text || '');
        return typeof DOMPurify !== 'undefined' ? DOMPurify.sanitize(raw) : raw;
    }
    return escapeHtml(text);
}

function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}
