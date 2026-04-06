// sensor.js — eBPF Security Sensor Dashboard
// Simulation engine + UI renderer

const SYSCALLS = {
  exec:  [{nr:59,name:'execve',cat:'exec'},{nr:322,name:'execveat',cat:'exec'},{nr:56,name:'clone',cat:'exec'},{nr:57,name:'fork',cat:'exec'}],
  net:   [{nr:41,name:'socket',cat:'net'},{nr:42,name:'connect',cat:'net'},{nr:43,name:'accept',cat:'net'},{nr:49,name:'bind',cat:'net'},{nr:44,name:'sendto',cat:'net'},{nr:45,name:'recvfrom',cat:'net'}],
  fs:    [{nr:257,name:'openat',cat:'fs'},{nr:217,name:'getdents64',cat:'fs'},{nr:77,name:'ftruncate',cat:'fs'},{nr:87,name:'unlink',cat:'fs'},{nr:80,name:'chdir',cat:'fs'},{nr:0,name:'read',cat:'fs'},{nr:1,name:'write',cat:'fs'}],
  priv:  [{nr:105,name:'setuid',cat:'priv'},{nr:101,name:'ptrace',cat:'priv'},{nr:319,name:'memfd_create',cat:'priv'},{nr:308,name:'setns',cat:'priv'},{nr:157,name:'prctl',cat:'priv'},{nr:92,name:'chown',cat:'priv'}],
};
const ALL_SYSCALLS = Object.values(SYSCALLS).flat();

const SCORE_MAP = {
  execve:5, execveat:5, clone:4, fork:3,
  socket:20, connect:15, accept:25, bind:30, sendto:10, recvfrom:5,
  openat:5, getdents64:8, ftruncate:60, unlink:15, chdir:3, read:2, write:4,
  setuid:80, ptrace:40, memfd_create:70, setns:50, prctl:10, chown:20,
};

const SENSITIVE_PATHS = ['/etc/shadow','/etc/passwd','/.ssh/id_rsa','/var/log/auth.log','/proc/1/','/root/.bash_history'];
const BENIGN_PATHS    = ['/usr/lib/x86_64/','/proc/self/maps','/dev/null','/tmp/work-','/home/ubuntu/'];

const ATTACK_PATTERNS = {
  recon:   [
    {name:'getdents64',cat:'fs',path:'/etc/'},
    {name:'openat',cat:'fs',path:'/etc/passwd'},
    {name:'openat',cat:'fs',path:'/etc/shadow'},
    {name:'socket',cat:'net',path:'AF_INET'},
    {name:'connect',cat:'net',path:'192.168.1.100:4444'},
  ],
  privesc: [
    {name:'openat',cat:'fs',path:'/proc/1/status'},
    {name:'openat',cat:'fs',path:'/etc/sudoers'},
    {name:'execve',cat:'exec',path:'sudo bash'},
    {name:'setuid',cat:'priv',path:'uid=0'},
    {name:'execve',cat:'exec',path:'/bin/bash'},
  ],
  fileless:[
    {name:'socket',cat:'net',path:'AF_INET'},
    {name:'connect',cat:'net',path:'attacker.io:443'},
    {name:'memfd_create',cat:'priv',path:'memfd:payload'},
    {name:'openat',cat:'fs',path:'/proc/self/fd/3'},
    {name:'execve',cat:'exec',path:'/proc/self/fd/3'},
  ],
  exfil:   [
    {name:'getdents64',cat:'fs',path:'/home/'},
    {name:'openat',cat:'fs',path:'/.ssh/id_rsa'},
    {name:'read',cat:'fs',path:'[fd:3]'},
    {name:'socket',cat:'net',path:'AF_INET'},
    {name:'connect',cat:'net',path:'185.220.101.5:1337'},
    {name:'ftruncate',cat:'fs',path:'/var/log/auth.log'},
  ],
};

const RULES = [
  {id:'R001',name:'Sensitive file access',syscalls:['openat'],score:30,cat:'fs',flag:'R001'},
  {id:'R002',name:'Raw socket creation',syscalls:['socket'],score:40,cat:'net',flag:'R002'},
  {id:'R003',name:'Fileless execution',syscalls:['memfd_create'],score:70,cat:'priv',flag:'R003'},
  {id:'R004',name:'Log wiping',syscalls:['ftruncate'],score:60,cat:'fs',flag:'R004'},
  {id:'R005',name:'Namespace escape',syscalls:['setns'],score:50,cat:'priv',flag:'R005'},
  {id:'R006',name:'UID escalation',syscalls:['setuid'],score:80,cat:'priv',flag:'R006'},
  {id:'R007',name:'Directory enumeration',syscalls:['getdents64'],score:8,cat:'fs',flag:'R007'},
  {id:'R008',name:'ptrace attach',syscalls:['ptrace'],score:40,cat:'priv',flag:'R008'},
  {id:'R009',name:'Outbound connection',syscalls:['connect'],score:15,cat:'net',flag:'R009'},
  {id:'R010',name:'Reverse shell listener',syscalls:['bind','accept'],score:25,cat:'net',flag:'R010'},
];

// ── State ──────────────────────────────────────────────────────────────────
let events = [], sessions = {}, sessionOrder = [], sessionPool = [];
let alerts = 0, running = true, filter = 'all', selectedSession = null;
let eps = 0, epsCount = 0, startTime = Date.now(), alertQueue = [];
const syscallCounts = {};
let attackQueue = [];

// ── Helpers ────────────────────────────────────────────────────────────────
const randInt  = (a,b) => Math.floor(Math.random()*(b-a+1))+a;
const randItem = arr  => arr[randInt(0,arr.length-1)];
const fmtTime  = ts  => { const d=new Date(ts); return [d.getHours(),d.getMinutes(),d.getSeconds()].map(v=>String(v).padStart(2,'0')).join(':') + '.' + String(Math.floor(d.getMilliseconds()/10)).padStart(2,'0'); };
const genSid   = ()  => 'sess_' + Math.random().toString(16).slice(2,10);
const genPid   = ()  => randInt(1000,32000);

function scoreClass(s){ return s>100?'score-high':s>50?'score-mid':'score-low'; }
function pillClass(s) { return s>100?'s-high':s>50?'s-mid':'s-low'; }

// ── Session management ─────────────────────────────────────────────────────
function ensureSessions(){
  while(sessionPool.length < 3){
    const sid=genSid(), pid=genPid(), uid=randItem([33,1000,1001]);
    const sess = {sid,pid,uid,score:0,chain:[],triggered:[],entry:Date.now(),alerted:false};
    sessions[sid] = sess;
    sessionOrder.push(sid);
    sessionPool.push(sess);
  }
}

// ── Event engine ───────────────────────────────────────────────────────────
function addEvent(sc, path, sid, extraDelta){
  const sess = sessions[sid];
  if(!sess) return;
  let delta = SCORE_MAP[sc.name] || 3;
  if(extraDelta !== undefined) delta = extraDelta;
  if(path && SENSITIVE_PATHS.some(p => path.includes(p.replace(/\//g,'').slice(0,6)))) delta += 25;

  sess.score += delta;
  sess.chain.push(sc.name);
  sess.last = Date.now();

  // flag triggered rules
  RULES.forEach(r => {
    if(!sess.triggered.includes(r.flag) && r.syscalls.includes(sc.name)){
      sess.triggered.push(r.flag);
    }
  });

  const ev = {ts:Date.now(), pid:sess.pid, syscall:sc.name, nr:sc.nr||0, path:path||'', sid, delta, cat:sc.cat};
  events.unshift(ev);
  if(events.length > 300) events.pop();

  epsCount++;
  syscallCounts[sc.name] = (syscallCounts[sc.name]||0)+1;

  if(sess.score > 100 && !sess.alerted){
    sess.alerted = true;
    alerts++;
    triggerAlert(sid, sess);
  }
}

function genBackground(){
  if(!running) return;
  const sc  = randItem(ALL_SYSCALLS);
  const path = sc.cat==='fs' ? randItem(BENIGN_PATHS)+Math.random().toString(36).slice(2,8) : '';
  const sess = randItem(sessionPool);
  if(sess) addEvent(sc, path, sess.sid);
}

// ── Attack injection ───────────────────────────────────────────────────────
function injectAttack(type){
  const pattern = ATTACK_PATTERNS[type];
  if(!pattern) return;
  const sid=genSid(), pid=genPid(), uid=randItem([33,1000]);
  const sess = {sid,pid,uid,score:0,chain:[],triggered:[],entry:Date.now(),alerted:false,attack:type};
  sessions[sid] = sess;
  sessionOrder.unshift(sid);
  sessionPool.unshift(sess);
  const t0 = Date.now();
  pattern.forEach((step,i) => {
    const sc = {name:step.name, nr:0, cat:step.cat};
    attackQueue.push({sc, path:step.path, sid, fireAt: t0 + i*700});
  });
}

function tickAttacks(){
  const now = Date.now();
  attackQueue = attackQueue.filter(a => {
    if(now >= a.fireAt){ addEvent(a.sc, a.path, a.sid); return false; }
    return true;
  });
}

// ── Alerts ─────────────────────────────────────────────────────────────────
function triggerAlert(sid, sess){
  alertQueue.push({sid, score:Math.round(sess.score), chain:sess.chain.slice(-5), attack:sess.attack});
  if(alertQueue.length > 2) alertQueue.shift();
  renderAlerts();
}

function renderAlerts(){
  const c = document.getElementById('alert-container');
  if(!alertQueue.length){c.innerHTML='';return;}
  const a = alertQueue[alertQueue.length-1];
  c.innerHTML = `<div class="alert-banner">
    ⚠&nbsp;&nbsp;ALERT: <strong>${a.sid}</strong>&nbsp;— score=${a.score}&nbsp;— chain=[${a.chain.join('→')}]${a.attack?' ('+a.attack.toUpperCase()+')':''}
  </div>`;
}

// ── Render: Feed ───────────────────────────────────────────────────────────
function renderFeed(){
  const feed = document.getElementById('event-feed');
  const filtered = filter==='all' ? events : events.filter(e=>e.cat===filter);
  if(!filtered.length){feed.innerHTML='<div class="empty">No events match filter</div>';return;}
  feed.innerHTML = filtered.slice(0,100).map(e=>`
    <div class="event-row" onclick="selectSession('${e.sid}')">
      <span class="ev-time">${fmtTime(e.ts)}</span>
      <span class="ev-pid">${e.pid}</span>
      <span class="ev-syscall">${e.syscall}</span>
      <span class="ev-args">${e.path||'—'}</span>
      <span class="score-pill ${pillClass(e.delta)}">+${Math.round(e.delta)}</span>
    </div>`).join('');
}

// ── Render: Sessions ───────────────────────────────────────────────────────
function renderSessions(){
  const list = document.getElementById('session-list');
  const sl = sessionOrder.map(sid=>sessions[sid]).filter(Boolean).sort((a,b)=>b.score-a.score);
  document.getElementById('sess-count').textContent = sl.length+' sessions';
  if(!sl.length){list.innerHTML='<div class="empty">No sessions</div>';return;}
  list.innerHTML = sl.map(s=>{
    const cls = scoreClass(s.score);
    const active = selectedSession===s.sid ? 'active' : '';
    const chain = s.chain.slice(-6);
    return `<div class="session-row ${active}" onclick="selectSession('${s.sid}')">
      <div class="sess-head">
        <span class="sess-id">${s.sid}</span>
        <span class="sess-score ${cls}">${Math.round(s.score)}</span>
      </div>
      <div class="chain-bar">
        ${chain.map((c,i)=>`<span class="chain-tag${i===chain.length-1?' triggered':''}">${c}</span>`).join('')}
      </div>
      <div class="sess-meta">pid:${s.pid} · uid:${s.uid} · ${s.chain.length} events${s.attack?' · '+s.attack.toUpperCase():''}</div>
    </div>`;
  }).join('');
}

// ── Render: Detail ─────────────────────────────────────────────────────────
function selectSession(sid){
  selectedSession = sid;
  const sess = sessions[sid];
  if(!sess) return;
  const dp = document.getElementById('detail-panel');
  dp.style.display = 'block';
  const scoreItems = RULES.filter(r => sess.triggered.includes(r.flag));
  const chainNodes = sess.chain.slice(-9);
  document.getElementById('detail-content').innerHTML = `
    <div class="detail-grid">
      <div class="detail-cell"><div class="cell-label">Session ID</div><div class="cell-value" style="font-size:13px">${sid}</div></div>
      <div class="detail-cell"><div class="cell-label">Threat Score</div>
        <div class="cell-value" style="font-size:22px;font-weight:700" class="${scoreClass(sess.score)}">${Math.round(sess.score)}
          ${sess.score>100?'<span class="badge badge-live" style="font-size:10px;margin-left:8px">ALERT</span>':''}
        </div>
      </div>
      <div class="detail-cell"><div class="cell-label">Root PID / UID</div><div class="cell-value">${sess.pid} / ${sess.uid}</div></div>
      <div class="detail-cell"><div class="cell-label">Total Events</div><div class="cell-value">${sess.chain.length}</div></div>
    </div>
    <div style="margin-bottom:12px">
      <div class="detail-title" style="margin-bottom:6px">Syscall Chain (last 9)</div>
      <div class="chain-visual">
        ${chainNodes.map((n,i)=>`<span class="chain-node${i===chainNodes.length-1?' highlight':''}">${n}</span>${i<chainNodes.length-1?'<span class="chain-arrow">→</span>':''}`).join('')}
      </div>
    </div>
    ${scoreItems.length?`<div>
      <div class="detail-title" style="margin-bottom:6px">Triggered Rules</div>
      <div class="score-breakdown">
        ${scoreItems.slice(0,6).map(r=>`
          <span class="sb-signal">${r.id}: ${r.name}</span>
          <div class="sb-bar-wrap"><div class="sb-bar" style="width:${Math.min(100,(r.score/80)*100)}%"></div></div>
          <span class="sb-val">+${r.score}</span>`).join('')}
      </div>
    </div>`:''}`;
}

// ── Render: Metrics ────────────────────────────────────────────────────────
function renderMetrics(){
  document.getElementById('m-eps').textContent  = Math.round(eps);
  document.getElementById('m-sess').textContent = sessionOrder.length;
  document.getElementById('m-alerts').textContent = alerts;
  const top = Object.entries(syscallCounts).sort((a,b)=>b[1]-a[1])[0];
  document.getElementById('m-top').textContent  = top ? top[0] : '—';
  const up = Math.round((Date.now()-startTime)/1000);
  document.getElementById('uptime-badge').textContent = 'uptime: '+up+'s';
}

// ── Render: Rules ──────────────────────────────────────────────────────────
function renderRules(){
  const el = document.getElementById('rules-list');
  const hits = (r) => Object.values(sessions).filter(s=>s.triggered&&s.triggered.includes(r.flag)).length;
  el.innerHTML = `<div class="rules-header"><span>ID</span><span>Signal</span><span>Syscalls</span><span>Score</span><span>Hits</span></div>` +
    RULES.map(r=>{
      const h = hits(r);
      return `<div class="rule-row">
        <span style="color:var(--text-tertiary)">${r.id}</span>
        <span style="color:var(--text-primary)">${r.name}</span>
        <span style="color:var(--accent-blue);overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${r.syscalls.join(', ')}</span>
        <span style="color:var(--accent-yellow)">+${r.score}</span>
        <span style="color:${h>0?'var(--accent-red)':'var(--text-tertiary)'}">${h}</span>
      </div>`;
    }).join('');
}

// ── Code content ───────────────────────────────────────────────────────────
function loadCodeBlocks(){
  document.getElementById('ebpf-code').innerHTML = ebpfCode();
  document.getElementById('python-code').innerHTML = pythonCode();
  document.getElementById('setup-guide').innerHTML = setupGuide();
}

function ebpfCode(){
  return `<span class="cm">// src/sensor/ebpf_sensor.c</span>
<span class="cm">// Compile: clang -O2 -target bpf -c ebpf_sensor.c -o ebpf_sensor.o</span>
<span class="cm">// Or load via BCC (see sensor_loader.py)</span>

<span class="kw">#include</span> <span class="str">&lt;linux/bpf.h&gt;</span>
<span class="kw">#include</span> <span class="str">&lt;bpf/bpf_helpers.h&gt;</span>
<span class="kw">#include</span> <span class="str">&lt;linux/sched.h&gt;</span>
<span class="kw">#include</span> <span class="str">&lt;linux/ptrace.h&gt;</span>

<span class="cm">/* Session state stored per-PID in a hash map */</span>
<span class="kw">struct</span> session_t {
    __u64 session_id;
    __u32 root_pid;
    __u32 uid_original;
    __u32 uid_current;
    __u64 entry_ts;
    __u64 last_event_ts;
    __u32 score;
    __u32 flags;          <span class="cm">// bitmask of triggered rules</span>
    __u32 netns_inode;
    __u8  alerted;
};

<span class="kw">struct</span> {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, <span class="nm">4096</span>);
    __type(key,   __u32);           <span class="cm">// pid</span>
    __type(value, <span class="kw">struct</span> session_t);
} sessions SEC(<span class="str">".maps"</span>);

<span class="cm">/* Ring buffer — zero-copy delivery to userspace */</span>
<span class="kw">struct</span> {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, <span class="nm">1</span> &lt;&lt; <span class="nm">20</span>);   <span class="cm">// 1 MB</span>
} events SEC(<span class="str">".maps"</span>);

<span class="kw">struct</span> event_t {
    __u64 timestamp;
    __u32 pid;
    __u32 ppid;
    __u32 syscall_nr;
    __u64 session_id;
    __u32 score_delta;
    <span class="kw">char</span>  comm[<span class="nm">16</span>];
    <span class="kw">char</span>  path[<span class="nm">64</span>];
    __u8  cat;   <span class="cm">// 0=exec 1=net 2=fs 3=priv</span>
};

<span class="cm">/* Helper: get or create session for current PID */</span>
<span class="kw">static</span> __always_inline <span class="kw">struct</span> session_t *
<span class="fn">get_or_create_session</span>(__u32 pid, __u32 uid) {
    <span class="kw">struct</span> session_t *sess = bpf_map_lookup_elem(&amp;sessions, &amp;pid);
    <span class="kw">if</span> (sess) <span class="kw">return</span> sess;
    <span class="kw">struct</span> session_t new = {};
    new.session_id  = bpf_ktime_get_ns() ^ ((__u64)pid &lt;&lt; <span class="nm">32</span>);
    new.root_pid    = pid;
    new.uid_original = uid;
    new.uid_current  = uid;
    new.entry_ts    = bpf_ktime_get_ns();
    bpf_map_update_elem(&amp;sessions, &amp;pid, &amp;new, BPF_NOEXIST);
    <span class="kw">return</span> bpf_map_lookup_elem(&amp;sessions, &amp;pid);
}

SEC(<span class="str">"tracepoint/syscalls/sys_enter_execve"</span>)
<span class="kw">int</span> <span class="fn">trace_execve</span>(<span class="kw">struct</span> trace_event_raw_sys_enter *ctx) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> <span class="nm">32</span>;
    __u32 uid = bpf_get_current_uid_gid() &amp; <span class="nm">0xFFFFFFFF</span>;
    <span class="kw">struct</span> session_t *sess = <span class="fn">get_or_create_session</span>(pid, uid);
    <span class="kw">if</span> (!sess) <span class="kw">return</span> <span class="nm">0</span>;
    sess->score += <span class="nm">5</span>;
    sess->last_event_ts = bpf_ktime_get_ns();
    <span class="kw">struct</span> event_t *e = bpf_ringbuf_reserve(&amp;events, <span class="kw">sizeof</span>(*e), <span class="nm">0</span>);
    <span class="kw">if</span> (!e) <span class="kw">return</span> <span class="nm">0</span>;
    e->timestamp  = bpf_ktime_get_ns();
    e->pid        = pid;
    e->syscall_nr = <span class="nm">59</span>;
    e->score_delta = <span class="nm">5</span>;
    e->session_id = sess->session_id;
    bpf_get_current_comm(&amp;e->comm, <span class="kw">sizeof</span>(e->comm));
    bpf_probe_read_user_str(&amp;e->path, <span class="kw">sizeof</span>(e->path),
                            (<span class="kw">void</span> *)ctx->args[<span class="nm">0</span>]);
    bpf_ringbuf_submit(e, <span class="nm">0</span>);
    <span class="kw">return</span> <span class="nm">0</span>;
}

SEC(<span class="str">"tracepoint/syscalls/sys_enter_openat"</span>)
<span class="kw">int</span> <span class="fn">trace_openat</span>(<span class="kw">struct</span> trace_event_raw_sys_enter *ctx) {
    __u32 pid = bpf_get_current_pid_tgid() >> <span class="nm">32</span>;
    __u32 uid = bpf_get_current_uid_gid() &amp; <span class="nm">0xFFFFFFFF</span>;
    <span class="kw">struct</span> session_t *sess = <span class="fn">get_or_create_session</span>(pid, uid);
    <span class="kw">if</span> (!sess) <span class="kw">return</span> <span class="nm">0</span>;
    <span class="kw">char</span> path[<span class="nm">64</span>];
    bpf_probe_read_user_str(path, <span class="kw">sizeof</span>(path), (<span class="kw">void</span> *)ctx->args[<span class="nm">1</span>]);
    __u32 delta = <span class="nm">5</span>;
    <span class="cm">/* Sensitive path heuristic — bump score */</span>
    <span class="kw">if</span> (path[<span class="nm">1</span>]=='e' &amp;&amp; path[<span class="nm">4</span>]=='/' &amp;&amp; path[<span class="nm">5</span>]=='s') delta = <span class="nm">30</span>; <span class="cm">// /etc/shadow</span>
    <span class="kw">if</span> (path[<span class="nm">1</span>]=='r' &amp;&amp; path[<span class="nm">2</span>]=='o' &amp;&amp; path[<span class="nm">3</span>]=='o') delta = <span class="nm">35</span>; <span class="cm">// /root/</span>
    sess->score += delta;
    <span class="kw">return</span> <span class="nm">0</span>;
}

SEC(<span class="str">"tracepoint/syscalls/sys_enter_socket"</span>)
<span class="kw">int</span> <span class="fn">trace_socket</span>(<span class="kw">struct</span> trace_event_raw_sys_enter *ctx) {
    __u32 pid = bpf_get_current_pid_tgid() >> <span class="nm">32</span>;
    __u32 uid = bpf_get_current_uid_gid() &amp; <span class="nm">0xFFFFFFFF</span>;
    <span class="kw">struct</span> session_t *sess = <span class="fn">get_or_create_session</span>(pid, uid);
    <span class="kw">if</span> (!sess) <span class="kw">return</span> <span class="nm">0</span>;
    __u32 family = (__u32)ctx->args[<span class="nm">0</span>];
    __u32 delta  = (family == <span class="nm">17</span>) ? <span class="nm">40</span> : <span class="nm">20</span>; <span class="cm">// AF_PACKET = raw</span>
    sess->score += delta;
    sess->flags |= (<span class="nm">1</span> &lt;&lt; <span class="nm">1</span>);  <span class="cm">// R002 flag</span>
    <span class="kw">return</span> <span class="nm">0</span>;
}

SEC(<span class="str">"tracepoint/syscalls/sys_enter_setuid"</span>)
<span class="kw">int</span> <span class="fn">trace_setuid</span>(<span class="kw">struct</span> trace_event_raw_sys_enter *ctx) {
    __u32 pid = bpf_get_current_pid_tgid() >> <span class="nm">32</span>;
    __u32 new_uid = (__u32)ctx->args[<span class="nm">0</span>];
    <span class="kw">struct</span> session_t *sess = bpf_map_lookup_elem(&amp;sessions, &amp;pid);
    <span class="kw">if</span> (sess) {
        sess->uid_current = new_uid;
        sess->score += <span class="nm">80</span>;
        sess->flags |= (<span class="nm">1</span> &lt;&lt; <span class="nm">5</span>);  <span class="cm">// R006 flag</span>
    }
    <span class="kw">return</span> <span class="nm">0</span>;
}

SEC(<span class="str">"tracepoint/syscalls/sys_enter_memfd_create"</span>)
<span class="kw">int</span> <span class="fn">trace_memfd_create</span>(<span class="kw">struct</span> trace_event_raw_sys_enter *ctx) {
    __u32 pid = bpf_get_current_pid_tgid() >> <span class="nm">32</span>;
    __u32 uid = bpf_get_current_uid_gid() &amp; <span class="nm">0xFFFFFFFF</span>;
    <span class="kw">struct</span> session_t *sess = <span class="fn">get_or_create_session</span>(pid, uid);
    <span class="kw">if</span> (sess) {
        sess->score += <span class="nm">70</span>;
        sess->flags |= (<span class="nm">1</span> &lt;&lt; <span class="nm">2</span>);  <span class="cm">// R003 fileless flag</span>
    }
    <span class="kw">return</span> <span class="nm">0</span>;
}

<span class="kw">char</span> LICENSE[] SEC(<span class="str">"license"</span>) = <span class="str">"GPL"</span>;`;
}

function pythonCode(){
  return `<span class="cm">#!/usr/bin/env python3</span>
<span class="cm"># src/sensor/sensor_loader.py</span>
<span class="cm"># Requirements: pip install bcc</span>
<span class="cm"># Run: sudo python3 sensor_loader.py</span>

<span class="kw">from</span> bcc <span class="kw">import</span> BPF
<span class="kw">import</span> ctypes, json, time, os, signal, sys

SCORE_THRESHOLD = <span class="nm">100</span>
SESSION_TIMEOUT = <span class="nm">300</span>   <span class="cm"># seconds of inactivity → session ends</span>
OUTPUT_FILE     = <span class="str">"sessions_dump.json"</span>

<span class="kw">class</span> <span class="fn">SensorEvent</span>(ctypes.Structure):
    _fields_ = [
        (<span class="str">"timestamp"</span>,  ctypes.c_uint64),
        (<span class="str">"pid"</span>,        ctypes.c_uint32),
        (<span class="str">"ppid"</span>,       ctypes.c_uint32),
        (<span class="str">"syscall_nr"</span>, ctypes.c_uint32),
        (<span class="str">"session_id"</span>, ctypes.c_uint64),
        (<span class="str">"score_delta"</span>,ctypes.c_uint32),
        (<span class="str">"comm"</span>,       ctypes.c_char * <span class="nm">16</span>),
        (<span class="str">"path"</span>,       ctypes.c_char * <span class="nm">64</span>),
        (<span class="str">"cat"</span>,        ctypes.c_uint8),
    ]

SYSCALL_NAMES = {
    <span class="nm">59</span>: <span class="str">"execve"</span>,   <span class="nm">322</span>: <span class="str">"execveat"</span>, <span class="nm">56</span>: <span class="str">"clone"</span>,
    <span class="nm">257</span>: <span class="str">"openat"</span>,  <span class="nm">217</span>: <span class="str">"getdents64"</span>, <span class="nm">77</span>: <span class="str">"ftruncate"</span>,
    <span class="nm">41</span>: <span class="str">"socket"</span>,   <span class="nm">42</span>: <span class="str">"connect"</span>,  <span class="nm">43</span>: <span class="str">"accept"</span>,
    <span class="nm">49</span>: <span class="str">"bind"</span>,     <span class="nm">105</span>: <span class="str">"setuid"</span>,   <span class="nm">101</span>: <span class="str">"ptrace"</span>,
    <span class="nm">319</span>: <span class="str">"memfd_create"</span>, <span class="nm">308</span>: <span class="str">"setns"</span>, <span class="nm">157</span>: <span class="str">"prctl"</span>,
}

SCORE_MAP = {
    <span class="nm">59</span>:5, <span class="nm">322</span>:5, <span class="nm">56</span>:4, <span class="nm">257</span>:5, <span class="nm">217</span>:8, <span class="nm">77</span>:60,
    <span class="nm">41</span>:20, <span class="nm">42</span>:15, <span class="nm">43</span>:25, <span class="nm">49</span>:30, <span class="nm">105</span>:80,
    <span class="nm">101</span>:40, <span class="nm">319</span>:70, <span class="nm">308</span>:50, <span class="nm">157</span>:10,
}

SENSITIVE = [<span class="str">"/etc/shadow"</span>,<span class="str">"/etc/passwd"</span>,<span class="str">"/.ssh/"</span>,<span class="str">"/var/log/auth"</span>,<span class="str">"/root/"</span>]

sessions = {}
alerts   = []

<span class="kw">def</span> <span class="fn">score_event</span>(event):
    sc    = event.syscall_nr
    path  = event.path.decode(<span class="str">"utf-8"</span>, errors=<span class="str">"replace"</span>)
    delta = SCORE_MAP.get(sc, <span class="nm">2</span>)
    <span class="kw">if</span> <span class="fn">any</span>(s <span class="kw">in</span> path <span class="kw">for</span> s <span class="kw">in</span> SENSITIVE):
        delta += <span class="nm">25</span>
    <span class="kw">return</span> delta

<span class="kw">def</span> <span class="fn">handle_event</span>(cpu, data, size):
    event = ctypes.cast(data, ctypes.POINTER(SensorEvent)).contents
    sid   = event.session_id
    pid   = event.pid

    <span class="kw">if</span> sid <span class="kw">not in</span> sessions:
        sessions[sid] = {
            <span class="str">"pid"</span>: pid, <span class="str">"score"</span>: <span class="nm">0</span>, <span class="str">"chain"</span>: [],
            <span class="str">"start"</span>: time.time(), <span class="str">"last"</span>: time.time(),
            <span class="str">"alerted"</span>: <span class="nm">False</span>,
        }

    delta = <span class="fn">score_event</span>(event)
    sessions[sid][<span class="str">"score"</span>] += delta
    sessions[sid][<span class="str">"last"</span>]   = time.time()
    sc_name = SYSCALL_NAMES.get(event.syscall_nr, <span class="fn">f"sc#{event.syscall_nr}"</span>)
    sessions[sid][<span class="str">"chain"</span>].append(sc_name)

    path = event.path.decode(<span class="str">"utf-8"</span>, errors=<span class="str">"replace"</span>)[:40]
    <span class="fn">print</span>(<span class="fn">f"[{sc_name:15s}] pid={pid:<6} score={sessions[sid]['score']:<5} path={path}"</span>)

    <span class="kw">if</span> sessions[sid][<span class="str">"score"</span>] > SCORE_THRESHOLD <span class="kw">and not</span> sessions[sid][<span class="str">"alerted"</span>]:
        sessions[sid][<span class="str">"alerted"</span>] = <span class="nm">True</span>
        chain = sessions[sid][<span class="str">"chain"</span>][-<span class="nm">5</span>:]
        <span class="fn">print</span>(<span class="fn">f"\\n{'='*60}"</span>)
        <span class="fn">print</span>(<span class="fn">f"[ALERT] session={sid:#x} score={sessions[sid]['score']}"</span>)
        <span class="fn">print</span>(<span class="fn">f"        chain={' → '.join(chain)}"</span>)
        <span class="fn">print</span>(<span class="fn">f"{'='*60}\\n"</span>)
        alerts.append({<span class="str">"sid"</span>:sid, <span class="str">"score"</span>:sessions[sid][<span class="str">"score"</span>], <span class="str">"chain"</span>:chain})

<span class="kw">def</span> <span class="fn">expire_sessions</span>():
    now = time.time()
    expired = [sid <span class="kw">for</span> sid,s <span class="kw">in</span> sessions.items() <span class="kw">if</span> now-s[<span class="str">"last"</span>] > SESSION_TIMEOUT]
    <span class="kw">for</span> sid <span class="kw">in</span> expired:
        <span class="fn">print</span>(<span class="fn">f"[SESSION END] {sid:#x} — score={sessions[sid]['score']}"</span>)
        <span class="kw">del</span> sessions[sid]

<span class="kw">def</span> <span class="fn">dump_and_exit</span>(sig, frame):
    <span class="fn">print</span>(<span class="str">"\\nDumping sessions..."</span>)
    json.dump({<span class="str">"sessions"</span>:sessions,<span class="str">"alerts"</span>:alerts},
              <span class="fn">open</span>(OUTPUT_FILE,<span class="str">"w"</span>), indent=<span class="nm">2</span>, default=str)
    <span class="fn">print</span>(<span class="fn">f"Saved to {OUTPUT_FILE}"</span>)
    sys.exit(<span class="nm">0</span>)

signal.signal(signal.SIGINT, dump_and_exit)

b = BPF(src_file=<span class="str">"ebpf_sensor.c"</span>)
b[<span class="str">"events"</span>].open_ring_buffer(handle_event)

<span class="fn">print</span>(<span class="str">f"eBPF sensor running (PID {os.getpid()}). Ctrl-C to stop & dump."</span>)
expire_tick = time.time()

<span class="kw">while True</span>:
    b.ring_buffer_poll()
    <span class="kw">if</span> time.time() - expire_tick > <span class="nm">30</span>:
        <span class="fn">expire_sessions</span>()
        expire_tick = time.time()
    time.sleep(<span class="nm">0.05</span>)`;
}

function setupGuide(){
  return `
    <h3>1. Prerequisites</h3>
    <p>You need a Linux machine with kernel 5.8+ and root access. BCC must be installed for the Python loader.</p>
    <code>sudo apt install bpfcc-tools python3-bpfcc linux-headers-$(uname -r)
uname -r   # verify kernel version ≥ 5.8</code>

    <h3>2. Clone the repo</h3>
    <code>git clone https://github.com/yourusername/ebpf-sensor
cd ebpf-sensor</code>

    <h3>3. Option A — BCC loader (easiest)</h3>
    <p>Uses the Python BCC bindings to JIT-compile and load the eBPF program at runtime. No separate compile step needed.</p>
    <code>cd src/sensor
sudo python3 sensor_loader.py</code>

    <h3>4. Option B — libbpf / native (advanced)</h3>
    <p>Compile the eBPF object manually then attach with your own loader or <span class="inline-code">bpftool</span>.</p>
    <code>clang -O2 -target bpf -c src/sensor/ebpf_sensor.c -o ebpf_sensor.o
sudo bpftool prog load ebpf_sensor.o /sys/fs/bpf/sensor
sudo bpftool prog tracelog</code>

    <h3>5. Vercel dashboard (this app)</h3>
    <p>The dashboard is a static site — no backend required. Deploy to Vercel in one command.</p>
    <code>npm i -g vercel
vercel --prod</code>

    <h3>6. Running tests</h3>
    <p>To verify the sensor triggers correctly, run the included test scripts that simulate each attack pattern.</p>
    <code>sudo bash src/sensor/test_recon.sh
sudo bash src/sensor/test_privesc.sh</code>

    <h3>Notes</h3>
    <p>The dashboard (this page) is a browser-side simulation for visualization and education. The C and Python files in the tabs are the real production sensor code. The dashboard and sensor are independent — you can run either without the other.</p>`;
}

// ── Controls ───────────────────────────────────────────────────────────────
function toggleSim(btn){
  running = !running;
  btn.textContent = running ? '⏸ Pause' : '▶ Resume';
  btn.classList.toggle('active', running);
}

function setFilter(f, btn){
  filter = f;
  document.querySelectorAll('.filter-row .ctrl-btn').forEach(b=>b.classList.remove('active'));
  btn.classList.add('active');
}

function switchTab(id, btn){
  document.querySelectorAll('.tab').forEach(t=>t.classList.remove('active'));
  document.querySelectorAll('.tab-content').forEach(t=>t.classList.remove('active'));
  btn.classList.add('active');
  document.getElementById('tab-'+id).classList.add('active');
}

function clearAll(){
  events=[]; sessions={}; sessionOrder=[]; sessionPool=[];
  alerts=0; alertQueue=[]; attackQueue=[];
  Object.keys(syscallCounts).forEach(k=>delete syscallCounts[k]);
  selectedSession=null;
  document.getElementById('detail-panel').style.display='none';
  document.getElementById('alert-container').innerHTML='';
  ensureSessions();
}

// ── Main loop ──────────────────────────────────────────────────────────────
function start(){
  ensureSessions();
  loadCodeBlocks();
  setInterval(()=>{ if(running){ genBackground(); tickAttacks(); } }, 400);
  setInterval(()=>{ renderFeed(); renderSessions(); renderMetrics(); renderRules();
                    if(selectedSession) selectSession(selectedSession); }, 500);
  setInterval(()=>{ eps = eps*0.7 + epsCount*0.3; epsCount=0; }, 1000);
}

start();
