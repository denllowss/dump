#!/usr/bin/env node
'use strict';

/**
 * BANDWIDTH LIMITER - Enforcer Edition (Linux)
 *
 * Syarat:
 *  - Linux, Node.js >= 18, `npm i inquirer@8`
 *  - Jalankan sebagai root (sudo)
 *  - Paket: iproute2 (ip, tc), iptables (opsional: ip6tables, conntrack, hostapd_cli)
 *  - Mesin ini harus menjadi GATEWAY / ROUTER / HOTSPOT bagi device lain
 *    (trafik device lain harus lewat mesin ini, net.ipv4.ip_forward=1)
 *
 * Mode:
 *  - Interaktif : sudo node bandwidth-limiter.js
 *  - Daemon     : sudo node bandwidth-limiter.js --daemon [--interval=5] [--scan=60]
 *  - Service    : menu "Enforcer & Service" -> Install (jalan terus & auto-start saat boot)
 */

const fs = require('fs');
const path = require('path');
const os = require('os');
const dns = require('dns').promises;
const { execFile, execFileSync } = require('child_process');
const { promisify } = require('util');
const execFileAsync = promisify(execFile);

const argv = process.argv.slice(2);
const DAEMON = argv.includes('--daemon');
const argNum = (name, def) => {
  const a = argv.find((x) => x.startsWith(`--${name}=`));
  const n = a ? Number(a.split('=')[1]) : NaN;
  return Number.isFinite(n) && n > 0 ? n : def;
};
const CHECK_SECONDS = argNum('interval', 5);   // seberapa sering state diverifikasi & dipulihkan
const SCAN_SECONDS = argNum('scan', 60);       // seberapa sering jaringan dipindai ulang

if (argv.includes('--help') || argv.includes('-h')) {
  console.log(`Penggunaan:
  sudo node bandwidth-limiter.js                 Menu interaktif
  sudo node bandwidth-limiter.js --daemon        Enforcer berjalan terus (tanpa menu)
      --interval=5   Verifikasi limit tiap N detik (default 5)
      --scan=60      Scan device tiap N detik (default 60)`);
  process.exit(0);
}

const inquirer = DAEMON ? null : require('inquirer');

const isRoot = typeof process.getuid === 'function' && process.getuid() === 0;
const CONFIG_DIR = process.env.BWL_DIR ||
  (process.platform === 'linux' && isRoot ? '/etc/bandwidth-limiter' : os.homedir());
try { fs.mkdirSync(CONFIG_DIR, { recursive: true }); } catch (_) { /* abaikan */ }

const CONFIG_FILE = path.join(CONFIG_DIR, 'bandwidth-config.json');
const DEVICES_FILE = path.join(CONFIG_DIR, 'connected-devices.json');
const PID_FILE = path.join(CONFIG_DIR, 'daemon.pid');
const SERVICE_NAME = 'bandwidth-limiter';
const SERVICE_FILE = `/etc/systemd/system/${SERVICE_NAME}.service`;

const IFB_NAME = 'ifbbw0';
const CHAIN_FWD = 'BWLIMIT';
const CHAIN_IN = 'BWLIMIT_IN';
const DEFAULT_CLASS = 9999;
const FIRST_CLASS = 10;

const colors = {
  reset: '\x1b[0m', green: '\x1b[32m', red: '\x1b[31m', yellow: '\x1b[33m',
  cyan: '\x1b[36m', magenta: '\x1b[35m', gray: '\x1b[90m', bold: '\x1b[1m'
};
const success = (m) => console.log(`${colors.green}${colors.bold}✅ ${m}${colors.reset}`);
const error = (m) => console.log(`${colors.red}${colors.bold}❌ ${m}${colors.reset}`);
const info = (m) => console.log(`${colors.cyan}${colors.bold}ℹ️  ${m}${colors.reset}`);
const warn = (m) => console.log(`${colors.yellow}${colors.bold}⚠️  ${m}${colors.reset}`);
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// ───────────────────────── Helpers ─────────────────────────

function run(cmd, args, { allowFail = false } = {}) {
  try {
    return execFileSync(cmd, args, { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] });
  } catch (e) {
    if (allowFail) return null;
    const msg = ((e.stderr || e.message || '') + '').trim();
    throw new Error(`${cmd} ${args.join(' ')} -> ${msg}`);
  }
}
const tryRun = (cmd, args) => run(cmd, args, { allowFail: true });

const isV4 = (f) => f.family === 'IPv4' || f.family === 4;
const isIPv4 = (s) => /^(\d{1,3}\.){3}\d{1,3}$/.test(s) && s.split('.').every((n) => Number(n) <= 255);
const isMAC = (s) => /^([0-9a-f]{2}:){5}[0-9a-f]{2}$/i.test(s);
const toKbit = (mbps) => Math.max(8, Math.round(mbps * 1000));
const ipToInt = (ip) => ip.split('.').reduce((a, o) => ((a << 8) | Number(o)) >>> 0, 0);
const intToIp = (n) => [24, 16, 8, 0].map((s) => (n >>> s) & 255).join('.');
const mtimeOf = (f) => { try { return fs.statSync(f).mtimeMs; } catch (_) { return 0; } };

async function pool(items, size, fn) {
  let i = 0;
  await Promise.all(Array.from({ length: Math.min(size, items.length) }, async () => {
    while (i < items.length) {
      const item = items[i++];
      try { await fn(item); } catch (_) { /* abaikan */ }
    }
  }));
}

function loadJSON(file, fallback) {
  try {
    if (fs.existsSync(file)) return JSON.parse(fs.readFileSync(file, 'utf8'));
  } catch (_) { warn(`Gagal membaca ${path.basename(file)}`); }
  return fallback;
}
function saveJSON(file, data) {
  try { fs.writeFileSync(file, JSON.stringify(data, null, 2)); }
  catch (_) { warn(`Gagal menyimpan ${path.basename(file)}`); }
}

function daemonPid() {
  try {
    const pid = Number(fs.readFileSync(PID_FILE, 'utf8').trim());
    if (pid && pid !== process.pid) { process.kill(pid, 0); return pid; }
  } catch (_) { /* tidak berjalan */ }
  return null;
}

// ───────────────────────── Firewall (iptables / ip6tables) ─────────────────────────

class Firewall {
  constructor() {
    this.v6 = tryRun('which', ['ip6tables']) !== null;
  }

  _args(op, chain, match, tag) {
    return [op, chain, ...match, '-m', 'comment', '--comment', tag, '-j', 'DROP'];
  }
  _has(bin, chain, match, tag) {
    return tryRun(bin, this._args('-C', chain, match, tag)) !== null;
  }
  _add(bin, chain, match, tag, strict = true) {
    if (this._has(bin, chain, match, tag)) return;
    const a = this._args('-A', chain, match, tag);
    if (strict) run(bin, a); else tryRun(bin, a);
  }
  _del(bin, chain, match, tag) {
    for (let i = 0; i < 5; i++) {
      if (!this._has(bin, chain, match, tag)) break;
      tryRun(bin, this._args('-D', chain, match, tag));
    }
  }

  // Pastikan jump ke chain kita SELALU di posisi pertama (mengalahkan rule ACCEPT lain)
  _ensureChain(bin, hook, chain, strict) {
    tryRun(bin, ['-N', chain]);
    const out = tryRun(bin, ['-S', hook]) || '';
    const first = out.split('\n').find((l) => l.startsWith(`-A ${hook} `));
    if (first === `-A ${hook} -j ${chain}`) return;
    for (let i = 0; i < 5; i++) {
      if (tryRun(bin, ['-C', hook, '-j', chain]) === null) break;
      tryRun(bin, ['-D', hook, '-j', chain]);
    }
    if (strict) run(bin, ['-I', hook, '1', '-j', chain]);
    else tryRun(bin, ['-I', hook, '1', '-j', chain]);
  }

  ensureChain() {
    this._ensureChain('iptables', 'FORWARD', CHAIN_FWD, true);
    this._ensureChain('iptables', 'INPUT', CHAIN_IN, true);
    if (this.v6) {
      this._ensureChain('ip6tables', 'FORWARD', CHAIN_FWD, false);
      this._ensureChain('ip6tables', 'INPUT', CHAIN_IN, false);
    }
  }

  _ipTag(kind, ip) { return `bwl:${kind}:${ip}`; }
  _macTag(kind, mac) { return `bwl:${kind}:${mac.toUpperCase()}`; }
  _macMatch(mac) { return ['-m', 'mac', '--mac-source', mac]; }

  // Blokir total: IP + MAC, IPv4 + IPv6, forward + input
  block(dev, kind) {
    this.ensureChain();
    const ipT = this._ipTag(kind, dev.ipAddress);
    const macT = this._macTag(kind, dev.mac);
    this._add('iptables', CHAIN_FWD, ['-s', dev.ipAddress], ipT);
    this._add('iptables', CHAIN_FWD, ['-d', dev.ipAddress], ipT);
    this._add('iptables', CHAIN_IN, ['-s', dev.ipAddress], ipT);
    this._add('iptables', CHAIN_FWD, this._macMatch(dev.mac), macT);
    this._add('iptables', CHAIN_IN, this._macMatch(dev.mac), macT);
    if (this.v6) {
      this._add('ip6tables', CHAIN_FWD, this._macMatch(dev.mac), macT, false);
      this._add('ip6tables', CHAIN_IN, this._macMatch(dev.mac), macT, false);
    }
    // putuskan koneksi yang sudah berjalan
    tryRun('conntrack', ['-D', '-s', dev.ipAddress]);
    tryRun('conntrack', ['-D', '-d', dev.ipAddress]);
  }

  hasBlock(dev, kind) {
    return this._has('iptables', CHAIN_FWD, ['-s', dev.ipAddress], this._ipTag(kind, dev.ipAddress)) &&
      this._has('iptables', CHAIN_FWD, this._macMatch(dev.mac), this._macTag(kind, dev.mac));
  }

  unblockIp(ip, kind) {
    const t = this._ipTag(kind, ip);
    this._del('iptables', CHAIN_FWD, ['-s', ip], t);
    this._del('iptables', CHAIN_FWD, ['-d', ip], t);
    this._del('iptables', CHAIN_IN, ['-s', ip], t);
  }

  unblock(dev, kind) {
    this.unblockIp(dev.ipAddress, kind);
    const t = this._macTag(kind, dev.mac);
    this._del('iptables', CHAIN_FWD, this._macMatch(dev.mac), t);
    this._del('iptables', CHAIN_IN, this._macMatch(dev.mac), t);
    if (this.v6) {
      this._del('ip6tables', CHAIN_FWD, this._macMatch(dev.mac), t);
      this._del('ip6tables', CHAIN_IN, this._macMatch(dev.mac), t);
    }
  }

  // Device yang dilimit: IPv6 dimatikan agar tidak bisa lolos dari limit IPv4
  dropV6(dev) {
    if (!this.v6) return;
    this._ensureChain('ip6tables', 'FORWARD', CHAIN_FWD, false);
    this._add('ip6tables', CHAIN_FWD, this._macMatch(dev.mac), this._macTag('v6', dev.mac), false);
  }
  allowV6(dev) {
    if (!this.v6) return;
    this._del('ip6tables', CHAIN_FWD, this._macMatch(dev.mac), this._macTag('v6', dev.mac));
  }

  blockIface(iface) {
    this.ensureChain();
    const tag = `bwl:iface:${iface}`;
    this._add('iptables', CHAIN_FWD, ['-i', iface], tag);
    this._add('iptables', CHAIN_FWD, ['-o', iface], tag);
  }
  hasIfaceBlock(iface) {
    return this._has('iptables', CHAIN_FWD, ['-i', iface], `bwl:iface:${iface}`);
  }
  unblockIface(iface) {
    const tag = `bwl:iface:${iface}`;
    this._del('iptables', CHAIN_FWD, ['-i', iface], tag);
    this._del('iptables', CHAIN_FWD, ['-o', iface], tag);
  }

  flush() {
    const bins = this.v6 ? ['iptables', 'ip6tables'] : ['iptables'];
    for (const bin of bins) {
      for (const [hook, chain] of [['FORWARD', CHAIN_FWD], ['INPUT', CHAIN_IN]]) {
        for (let i = 0; i < 5; i++) {
          if (tryRun(bin, ['-C', hook, '-j', chain]) === null) break;
          tryRun(bin, ['-D', hook, '-j', chain]);
        }
        tryRun(bin, ['-F', chain]);
        tryRun(bin, ['-X', chain]);
      }
    }
  }
}

// ───────────────────────── Traffic Control (tc) ─────────────────────────

class TrafficControl {
  constructor() { this.ready = null; }

  _initRoot(dev) {
    tryRun('tc', ['qdisc', 'del', 'dev', dev, 'root']);
    run('tc', ['qdisc', 'add', 'dev', dev, 'root', 'handle', '1:', 'htb', 'default', String(DEFAULT_CLASS)]);
    this.setClass(dev, DEFAULT_CLASS, 10000000);
  }

  init(lan) {
    if (this.ready === lan) return;
    tryRun('modprobe', ['ifb', 'numifbs=0']);
    tryRun('ip', ['link', 'add', IFB_NAME, 'type', 'ifb']);
    run('ip', ['link', 'set', 'dev', IFB_NAME, 'up']);

    this._initRoot(lan);
    this._initRoot(IFB_NAME);

    // Ingress (upload dari client) dialihkan ke ifb supaya bisa dibatasi
    tryRun('tc', ['qdisc', 'del', 'dev', lan, 'ingress']);
    run('tc', ['qdisc', 'add', 'dev', lan, 'handle', 'ffff:', 'ingress']);
    run('tc', ['filter', 'add', 'dev', lan, 'parent', 'ffff:', 'protocol', 'all', 'prio', '1',
      'u32', 'match', 'u32', '0', '0', 'action', 'mirred', 'egress', 'redirect', 'dev', IFB_NAME]);
    this.ready = lan;
  }

  // Apakah struktur qdisc masih utuh? (bisa hilang jika interface restart / ada yang menghapus)
  healthy(lan) {
    const a = tryRun('tc', ['qdisc', 'show', 'dev', lan]) || '';
    const b = tryRun('tc', ['qdisc', 'show', 'dev', IFB_NAME]) || '';
    return /qdisc htb 1:/.test(a) && /qdisc ingress ffff:/.test(a) && /qdisc htb 1:/.test(b);
  }

  teardown(lan) {
    if (lan) {
      tryRun('tc', ['qdisc', 'del', 'dev', lan, 'root']);
      tryRun('tc', ['qdisc', 'del', 'dev', lan, 'ingress']);
    }
    tryRun('tc', ['qdisc', 'del', 'dev', IFB_NAME, 'root']);
    tryRun('ip', ['link', 'del', IFB_NAME]);
    this.ready = null;
  }

  setClass(dev, minor, kbit) {
    run('tc', ['class', 'replace', 'dev', dev, 'parent', '1:', 'classid', `1:${minor}`,
      'htb', 'rate', `${kbit}kbit`, 'ceil', `${kbit}kbit`]);
  }

  _setFilter(dev, minor, dir, ip) {
    tryRun('tc', ['filter', 'del', 'dev', dev, 'parent', '1:', 'prio', String(minor)]);
    run('tc', ['filter', 'add', 'dev', dev, 'protocol', 'ip', 'parent', '1:', 'prio', String(minor),
      'u32', 'match', 'ip', dir, `${ip}/32`, 'flowid', `1:${minor}`]);
  }

  hasFilter(dev, minor) {
    const out = tryRun('tc', ['filter', 'show', 'dev', dev, 'parent', '1:', 'prio', String(minor)]) || '';
    return out.includes(`flowid 1:${minor}`);
  }

  setDevice(lan, minor, ip, downMbps, upMbps) {
    this.setClass(lan, minor, toKbit(downMbps));
    this._setFilter(lan, minor, 'dst', ip);          // download client
    this.setClass(IFB_NAME, minor, toKbit(upMbps));
    this._setFilter(IFB_NAME, minor, 'src', ip);     // upload client
  }

  removeDevice(lan, minor) {
    for (const dev of [lan, IFB_NAME]) {
      tryRun('tc', ['filter', 'del', 'dev', dev, 'parent', '1:', 'prio', String(minor)]);
      tryRun('tc', ['class', 'del', 'dev', dev, 'classid', `1:${minor}`]);
    }
  }

  setDefault(lan, downMbps, upMbps) {
    this.setClass(lan, DEFAULT_CLASS, downMbps ? toKbit(downMbps) : 10000000);
    this.setClass(IFB_NAME, DEFAULT_CLASS, upMbps ? toKbit(upMbps) : 10000000);
  }

  classBytes(dev, minor) {
    const out = tryRun('tc', ['-s', 'class', 'show', 'dev', dev]);
    if (!out) return null;
    const chunk = out.split(/\n(?=class )/).find((c) => c.startsWith(`class htb 1:${minor} `));
    const m = chunk && chunk.match(/Sent (\d+) bytes/);
    return m ? Number(m[1]) : null;
  }
}

// ───────────────────────── Device Manager ─────────────────────────

class DeviceManager {
  constructor() { this.load(); }

  load() {
    this.devices = new Map(Object.entries(loadJSON(DEVICES_FILE, {})));
    this.mtime = mtimeOf(DEVICES_FILE);
  }
  reload() { if (mtimeOf(DEVICES_FILE) !== this.mtime) this.load(); }
  save() {
    saveJSON(DEVICES_FILE, Object.fromEntries(this.devices));
    this.mtime = mtimeOf(DEVICES_FILE);
  }

  upsert(mac, name, ipAddress) {
    mac = mac.toUpperCase();
    const ex = this.devices.get(mac);
    this.devices.set(mac, {
      mac, name: name || ex?.name || 'Device', ipAddress,
      addedAt: ex?.addedAt || new Date().toISOString(),
      status: ex?.status || 'CONNECTED',
      disconnectedAt: ex?.disconnectedAt
    });
    this.save();
    return this.devices.get(mac);
  }
  remove(mac) { this.devices.delete(mac); this.save(); }
  setStatus(mac, status) {
    const d = this.devices.get(mac);
    if (!d) return;
    d.status = status;
    if (status === 'DISCONNECTED') d.disconnectedAt = new Date().toISOString();
    this.save();
  }
  get(mac) { return this.devices.get(mac) || null; }
  getAll() { return [...this.devices.values()]; }
  getConnected() { return this.getAll().filter((d) => d.status === 'CONNECTED'); }
  getDisconnected() { return this.getAll().filter((d) => d.status === 'DISCONNECTED'); }
}

// ───────────────────────── Bandwidth Manager (config) ─────────────────────────

class BandwidthManager {
  constructor() { this.load(); }

  load() {
    const data = loadJSON(CONFIG_FILE, {});
    this.settings = {
      lanInterface: null, nextClassId: FIRST_CLASS, defaultPolicy: null, blockIPv6: true,
      ...(data.settings || {})
    };
    this.limits = new Map(Object.entries(data.limits || {}));
    this.mtime = mtimeOf(CONFIG_FILE);
  }
  reload() { if (mtimeOf(CONFIG_FILE) !== this.mtime) this.load(); }
  save() {
    saveJSON(CONFIG_FILE, { settings: this.settings, limits: Object.fromEntries(this.limits) });
    this.mtime = mtimeOf(CONFIG_FILE);
  }
  allocClassId() {
    const used = new Set(this.getAll().map((l) => l.classId).filter(Boolean));
    let id = this.settings.nextClassId;
    while (used.has(id)) id++;
    if (id >= DEFAULT_CLASS) throw new Error('Class ID habis, jalankan Reset Semua');
    this.settings.nextClassId = id + 1;
    this.save();
    return id;
  }
  set(limit) { this.limits.set(limit.identifier, limit); this.save(); }
  remove(id) { this.limits.delete(id); this.save(); }
  get(id) { return this.limits.get(id) || null; }
  getAll() { return [...this.limits.values()]; }
}

// ───────────────────────── Network Manager ─────────────────────────

class NetworkManager {
  getInterfaceType(name) {
    if (/^(wl|wifi|wlan|ap)/.test(name)) return '📡 WiFi';
    if (/^(docker|br-|veth|virbr)/.test(name)) return '🐳 Virtual';
    if (/^(eth|en)/.test(name)) return '🔌 Ethernet';
    return '🌐 Network';
  }

  getAllInterfaces() {
    const result = [];
    for (const [name, details] of Object.entries(os.networkInterfaces())) {
      if (name === 'lo' || name === IFB_NAME) continue;
      const v4 = details.find((a) => isV4(a) && !a.internal);
      if (!v4) continue;
      result.push({ name, type: this.getInterfaceType(name), status: 'UP', ipv4: v4.address, mac: v4.mac, cidr: v4.cidr });
    }
    return result;
  }

  localIPs() {
    return new Set(Object.values(os.networkInterfaces()).flat().filter(isV4).map((a) => a.address));
  }

  async scan(ifaceName) {
    const ifc = this.getAllInterfaces().find((i) => i.name === ifaceName);
    if (!ifc || !ifc.cidr) throw new Error(`Interface ${ifaceName} tidak ditemukan / belum punya IP`);

    let [ip, prefix] = ifc.cidr.split('/');
    prefix = Number(prefix);
    if (prefix < 24) prefix = 24; // batasi sweep maksimal 254 host
    const mask = (~0 << (32 - prefix)) >>> 0;
    const network = (ipToInt(ip) & mask) >>> 0;
    const broadcast = (network | (~mask >>> 0)) >>> 0;

    const own = this.localIPs();
    const hosts = [];
    for (let n = network + 1; n < broadcast; n++) {
      const h = intToIp(n);
      if (!own.has(h)) hosts.push(h);
    }
    const hostSet = new Set(hosts);

    // Ping sweep -> memancing ARP agar tabel neighbor terisi
    await pool(hosts, 64, (h) => execFileAsync('ping', ['-c', '1', '-W', '1', '-I', ifaceName, h]));
    await sleep(500);

    const out = tryRun('ip', ['-4', 'neigh', 'show', 'dev', ifaceName]) || '';
    const found = [];
    for (const line of out.split('\n')) {
      const m = line.match(/^(\d+\.\d+\.\d+\.\d+)\s+.*lladdr\s+([0-9a-f:]{17})\s+(\S+)/i);
      if (m && hostSet.has(m[1]) && !/FAILED|INCOMPLETE/.test(m[3])) {
        found.push({ ip: m[1], mac: m[2].toUpperCase() });
      }
    }
    return found;
  }

  async resolveName(ip, mac) {
    try {
      const names = await Promise.race([
        dns.reverse(ip),
        new Promise((_, rej) => setTimeout(() => rej(new Error('timeout')), 1000))
      ]);
      if (names && names[0]) return names[0];
    } catch (_) { /* fallback */ }
    return `Device-${mac.replace(/:/g, '').slice(-4)}`;
  }

  // Speed test nyata untuk koneksi internet mesin ini (Cloudflare)
  async runSpeedTest() {
    const base = 'https://speed.cloudflare.com';
    const opts = { cache: 'no-store', signal: AbortSignal.timeout(30000) };

    const pings = [];
    for (let i = 0; i < 5; i++) {
      const t = performance.now();
      const r = await fetch(`${base}/__down?bytes=0`, opts);
      await r.arrayBuffer();
      pings.push(performance.now() - t);
    }
    const ping = pings.reduce((a, b) => a + b, 0) / pings.length;
    const jitter = pings.slice(1).reduce((a, p, i) => a + Math.abs(p - pings[i]), 0) / (pings.length - 1);

    let t = performance.now();
    const res = await fetch(`${base}/__down?bytes=25000000`, opts);
    let bytes = 0;
    for await (const chunk of res.body) bytes += chunk.length;
    const downloadSpeed = (bytes * 8) / 1e6 / ((performance.now() - t) / 1000);

    const payload = Buffer.alloc(8_000_000, 1);
    t = performance.now();
    const up = await fetch(`${base}/__up`, { ...opts, method: 'POST', body: payload });
    await up.arrayBuffer();
    const uploadSpeed = (payload.length * 8) / 1e6 / ((performance.now() - t) / 1000);

    return { downloadSpeed, uploadSpeed, ping, jitter };
  }
}

// ───────────────────────── App ─────────────────────────

const SPEED_CHOICES = [
  { name: '🚫 Block (0 Mbps)', value: 0 },
  { name: '🐢 Sangat Lambat (1Mbps)', value: 1 },
  { name: '🐌 Lambat (5Mbps)', value: 5 },
  { name: '⚠️  Terbatas (10Mbps)', value: 10 },
  { name: '📱 Normal (20Mbps)', value: 20 },
  { name: '⚡ Cepat (50Mbps)', value: 50 },
  { name: '🚀 Sangat Cepat (100Mbps)', value: 100 },
  { name: '✨ Custom', value: 'custom' }
];

class App {
  constructor() {
    this.bw = new BandwidthManager();
    this.net = new NetworkManager();
    this.devices = new DeviceManager();
    this.tc = new TrafficControl();
    this.fw = new Firewall();
    this.problems = [];
    this.applied = new Map();   // identifier -> { sig, limit, ip } (apa yang sudah diterapkan di kernel)
    this.logger = () => {};
    this.busy = false;
    this.bgTimer = null;
    this.lastScan = 0;
    this.hasHostapd = tryRun('which', ['hostapd_cli']) !== null;
  }

  log(msg) { this.logger(msg); }

  // ── Pemeriksaan lingkungan ──
  preflight() {
    const p = [];
    if (process.platform !== 'linux') {
      p.push('Script ini hanya mendukung Linux (memakai tc & iptables).');
    } else {
      if (!isRoot) p.push('Harus dijalankan sebagai root: sudo node bandwidth-limiter.js');
      for (const cmd of ['ip', 'tc', 'iptables']) {
        if (tryRun('which', [cmd]) === null) p.push(`Perintah "${cmd}" tidak ditemukan (apt install iproute2 iptables).`);
      }
      try {
        if (fs.readFileSync('/proc/sys/net/ipv4/ip_forward', 'utf8').trim() === '0') {
          p.push('ip_forward=0: trafik device lain tidak diteruskan lewat mesin ini. Aktifkan: sysctl -w net.ipv4.ip_forward=1');
        }
      } catch (_) { /* abaikan */ }
    }
    this.problems = p;
    return p;
  }

  hardProblem() {
    return this.problems.some((p) => !p.startsWith('ip_forward'));
  }

  // ── Penerapan aturan ──
  sigOf(limit, dev) {
    return `${limit.download}|${limit.upload}|${limit.classId || ''}|${dev ? dev.ipAddress + dev.mac : ''}|${this.bw.settings.blockIPv6}`;
  }

  enforce(limit) {
    const lan = this.bw.settings.lanInterface;
    if (!lan) throw new Error('Interface LAN belum dipilih');
    this.tc.init(lan);
    this.fw.ensureChain();

    let dev = null;
    if (limit.type === 'interface') {
      if (limit.download === 0) {
        this.fw.blockIface(limit.identifier);
      } else {
        this.fw.unblockIface(limit.identifier);
        this.tc.setDefault(lan, limit.download, limit.upload);
      }
    } else {
      dev = this.devices.get(limit.identifier);
      if (!dev) throw new Error(`Device ${limit.identifier} tidak ditemukan`);
      if (limit.download === 0) {
        this.fw.block(dev, 'lim');
        this.fw.allowV6(dev);
        this.tc.removeDevice(lan, limit.classId);
      } else {
        this.fw.unblock(dev, 'lim');
        this.tc.setDevice(lan, limit.classId, dev.ipAddress, limit.download, limit.upload);
        if (this.bw.settings.blockIPv6) this.fw.dropV6(dev); else this.fw.allowV6(dev);
      }
    }
    this.applied.set(limit.identifier, { sig: this.sigOf(limit, dev), limit: { ...limit }, ip: dev?.ipAddress });
  }

  release(limit, ipOverride) {
    const lan = this.bw.settings.lanInterface;
    if (limit.type === 'interface') {
      this.fw.unblockIface(limit.identifier);
      if (lan && this.tc.ready === lan) this.tc.setDefault(lan, 0, 0);
    } else {
      const dev = this.devices.get(limit.identifier);
      if (dev) { this.fw.unblock(dev, 'lim'); this.fw.allowV6(dev); }
      const ip = ipOverride || dev?.ipAddress;
      if (!dev && ip) this.fw.unblockIp(ip, 'lim');
      if (lan && limit.classId) this.tc.removeDevice(lan, limit.classId);
    }
    this.applied.delete(limit.identifier);
  }

  isHealthy(l, dev) {
    const lan = this.bw.settings.lanInterface;
    if (l.type === 'interface') {
      if (l.download === 0) return this.fw.hasIfaceBlock(l.identifier);
      return this.tc.classBytes(lan, DEFAULT_CLASS) !== null;
    }
    if (l.download === 0) return this.fw.hasBlock(dev, 'lim');
    return this.tc.hasFilter(lan, l.classId) && this.tc.hasFilter(IFB_NAME, l.classId);
  }

  // Pastikan fondasi (qdisc tc + chain iptables) utuh; jika rusak/hilang, bangun ulang
  ensureBase() {
    const lan = this.bw.settings.lanInterface;
    if (!lan) throw new Error('Interface LAN belum dipilih');
    if (this.tc.ready === lan && !this.tc.healthy(lan)) {
      this.log('Struktur tc hilang, membangun ulang...');
      this.tc.ready = null;
      this.applied.clear();
    }
    this.tc.init(lan);
    this.fw.ensureChain();
  }

  // Bandingkan kondisi yang diinginkan (config) dengan kondisi nyata, lalu pulihkan yang menyimpang
  verifyAll() {
    const limits = this.bw.getAll();
    const ids = new Set(limits.map((l) => l.identifier));

    for (const [id, rec] of [...this.applied]) {
      if (!ids.has(id)) {
        try { this.release(rec.limit, rec.ip); this.log(`Limit ${id} dihapus`); } catch (_) { /* abaikan */ }
        this.applied.delete(id);
      }
    }

    for (const l of limits) {
      const dev = l.type === 'device' ? this.devices.get(l.identifier) : null;
      if (l.type === 'device' && !dev) continue;
      const rec = this.applied.get(l.identifier);
      if (!rec || rec.sig !== this.sigOf(l, dev) || !this.isHealthy(l, dev)) {
        try {
          this.enforce(l);
          this.log(`Limit diterapkan/dipulihkan: ${l.type === 'device' ? `${dev.name} (${dev.ipAddress})` : l.identifier} ${l.download === 0 ? 'BLOCK' : `↓${l.download} ↑${l.upload} Mbps`}`);
        } catch (e) {
          this.log(`GAGAL menerapkan ${l.identifier}: ${e.message}`);
        }
      }
    }

    // Device yang di-disconnect harus tetap terputus (dan di-kick jika WiFi hostapd)
    for (const d of this.devices.getDisconnected()) {
      try {
        if (!this.fw.hasBlock(d, 'disc')) {
          this.fw.block(d, 'disc');
          this.log(`Disconnect dipulihkan: ${d.name} (${d.ipAddress})`);
        }
        this.kick(d);
      } catch (e) {
        this.log(`GAGAL disconnect ${d.name}: ${e.message}`);
      }
    }
  }

  syncAll() {
    this.ensureBase();
    this.verifyAll();
  }

  // Paksa lepas device dari AP WiFi (hanya jika mesin ini menjalankan hostapd)
  kick(dev) {
    const lan = this.bw.settings.lanInterface;
    if (!this.hasHostapd || !lan || !/^(wl|wifi|wlan|ap)/.test(lan)) return;
    tryRun('hostapd_cli', ['-i', lan, 'deauthenticate', dev.mac.toLowerCase()]);
  }

  resetAll() {
    this.fw.flush();
    this.tc.teardown(this.bw.settings.lanInterface);
    this.applied.clear();
  }

  // ── Enforcer (loop yang menjaga aturan terus-menerus) ──
  async tick(doScan) {
    if (this.busy) return;
    this.busy = true;
    try {
      this.bw.reload();
      this.devices.reload();
      if (!this.bw.settings.lanInterface) {
        this.log('Interface LAN belum dipilih (jalankan menu interaktif sekali untuk memilih).');
        return;
      }
      if (this.hardProblem()) return;
      this.ensureBase();
      if (doScan) await this.scanNetwork({ quiet: true });
      this.verifyAll();
    } catch (e) {
      this.log(`Error enforcer: ${e.message}`);
    } finally {
      this.busy = false;
    }
  }

  async enforcerLoop() {
    while (true) {
      const doScan = Date.now() - this.lastScan >= SCAN_SECONDS * 1000;
      if (doScan) this.lastScan = Date.now();
      await this.tick(doScan);
      await sleep(CHECK_SECONDS * 1000);
    }
  }

  startBackgroundEnforcer() {
    if (this.bgTimer || daemonPid()) return;
    this.bgTimer = setInterval(() => {
      if (daemonPid()) { this.stopBackgroundEnforcer(); return; }
      const doScan = Date.now() - this.lastScan >= SCAN_SECONDS * 1000;
      if (doScan) this.lastScan = Date.now();
      this.tick(doScan);
    }, CHECK_SECONDS * 1000);
  }
  stopBackgroundEnforcer() {
    if (this.bgTimer) { clearInterval(this.bgTimer); this.bgTimer = null; }
  }

  async runDaemon() {
    const other = daemonPid();
    if (other) {
      console.error(`Daemon sudah berjalan (PID ${other}).`);
      process.exit(1);
    }
    try { fs.writeFileSync(PID_FILE, String(process.pid)); } catch (_) { /* abaikan */ }
    const cleanup = () => { try { fs.unlinkSync(PID_FILE); } catch (_) { /* abaikan */ } };
    process.on('exit', cleanup);
    process.on('SIGTERM', () => process.exit(0));
    process.on('SIGINT', () => process.exit(0));

    this.logger = (m) => console.log(`[${new Date().toISOString()}] ${m}`);
    this.preflight();
    this.problems.forEach((p) => this.log(`PERINGATAN: ${p}`));
    this.log(`Enforcer berjalan (verifikasi tiap ${CHECK_SECONDS}s, scan tiap ${SCAN_SECONDS}s). Konfigurasi: ${CONFIG_DIR}`);
    await this.enforcerLoop();
  }

  // ── Service systemd ──
  installService() {
    if (process.platform !== 'linux') throw new Error('systemd hanya ada di Linux');
    if (!isRoot) throw new Error('Butuh root untuk install service');
    if (tryRun('which', ['systemctl']) === null) throw new Error('systemctl tidak ditemukan');
    const unit = `[Unit]
Description=Bandwidth Limiter Enforcer
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
Environment=BWL_DIR=${CONFIG_DIR}
ExecStart="${process.execPath}" "${path.resolve(__filename)}" --daemon --interval=${CHECK_SECONDS} --scan=${SCAN_SECONDS}
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
`;
    fs.writeFileSync(SERVICE_FILE, unit);
    run('systemctl', ['daemon-reload']);
    run('systemctl', ['enable', '--now', SERVICE_NAME]);
  }

  uninstallService() {
    if (!isRoot) throw new Error('Butuh root');
    tryRun('systemctl', ['disable', '--now', SERVICE_NAME]);
    try { fs.unlinkSync(SERVICE_FILE); } catch (_) { /* abaikan */ }
    tryRun('systemctl', ['daemon-reload']);
  }

  // ── Interface LAN ──
  async ensureLanInterface() {
    const ifaces = this.net.getAllInterfaces();
    const cur = this.bw.settings.lanInterface;
    if (cur && ifaces.some((i) => i.name === cur)) return cur;
    if (ifaces.length === 0) throw new Error('Tidak ada network interface aktif');
    const { name } = await inquirer.prompt([{
      type: 'list', name: 'name',
      message: `${colors.cyan}Pilih interface LAN (yang terhubung ke device klien):${colors.reset}`,
      choices: ifaces.map((i) => ({ name: `${i.type} ${i.name} (${i.ipv4})`, value: i.name }))
    }]);
    this.switchLan(name);
    return name;
  }

  switchLan(name) {
    if (this.bw.settings.lanInterface === name) return;
    try { this.resetAll(); } catch (_) { /* abaikan */ }
    this.bw.settings.lanInterface = name;
    this.bw.save();
    try { this.syncAll(); } catch (e) { warn(`Gagal menerapkan ulang: ${e.message}`); }
  }

  // ── UI ──
  enforcerStatusText() {
    const pid = daemonPid();
    if (pid) return `${colors.green}🛡️  Enforcer: daemon aktif (PID ${pid})${colors.reset}`;
    if (this.bgTimer) return `${colors.yellow}🛡️  Enforcer: aktif selama menu ini terbuka (install service agar permanen)${colors.reset}`;
    return `${colors.red}🛡️  Enforcer: tidak aktif${colors.reset}`;
  }

  showBanner() {
    console.clear();
    console.log(`${colors.cyan}${colors.bold}
╔════════════════════════════════════════════════════╗
║    🌐 BANDWIDTH LIMITER - Enforcer Edition 🌐     ║
║  Auto-Detect | Paksa Limit | Paksa Disconnect    ║
╚════════════════════════════════════════════════════╝
${colors.reset}`);
    console.log(`${colors.gray}   Interface LAN: ${this.bw.settings.lanInterface || '(belum dipilih)'}   Config: ${CONFIG_DIR}${colors.reset}`);
    console.log(`   ${this.enforcerStatusText()}`);
    const pol = this.bw.settings.defaultPolicy;
    console.log(`${colors.gray}   Device baru: ${!pol ? 'dibiarkan' : pol.download === 0 ? 'langsung DIBLOKIR' : `dibatasi ↓${pol.download} ↑${pol.upload} Mbps`}${colors.reset}`);
    this.problems.forEach((p) => warn(p));
  }

  showActiveLimits() {
    const limits = this.bw.getAll();
    const disc = this.devices.getDisconnected();
    if (limits.length === 0 && disc.length === 0) {
      console.log(`${colors.gray}   (Belum ada limit yang aktif)\n${colors.reset}`);
      return;
    }
    if (limits.length) console.log(`${colors.magenta}${colors.bold}\n📦 Active Limits:${colors.reset}`);
    limits.forEach((l, i) => {
      const dev = l.type === 'device' ? this.devices.get(l.identifier) : null;
      const label = dev ? `${dev.name} (${dev.ipAddress})` : l.identifier;
      const speed = l.download === 0
        ? `${colors.red}🚫 BLOCKED${colors.reset}`
        : `${colors.cyan}↓ ${l.download}Mbps ↑ ${l.upload}Mbps${colors.reset}`;
      console.log(`${colors.gray}   ${i + 1}. ${l.type === 'device' ? '📱' : '🌐'} ${label}${colors.reset}`);
      console.log(`      ${speed}`);
      console.log(`${colors.gray}      ⏰ ${l.timestamp}${colors.reset}\n`);
    });
    if (disc.length) {
      console.log(`${colors.red}${colors.bold}\n⛔ Disconnected (dijaga terus):${colors.reset}`);
      disc.forEach((d) => console.log(`${colors.red}   - ${d.name} (${d.ipAddress})${colors.reset}`));
      console.log();
    }
  }

  async askSpeed(message) {
    const { speedType } = await inquirer.prompt([{
      type: 'list', name: 'speedType', message: `${colors.cyan}${message}${colors.reset}`, choices: SPEED_CHOICES
    }]);
    if (speedType === 'custom') {
      const ok = (v) => (Number.isFinite(v) && v >= 0) || 'Harus angka >= 0';
      const { download } = await inquirer.prompt([
        { type: 'number', name: 'download', message: 'Download (Mbps) [0 = block]:', default: 10, validate: ok }
      ]);
      if (download === 0) return { download: 0, upload: 0 };
      const { upload } = await inquirer.prompt([{
        type: 'number', name: 'upload', message: 'Upload (Mbps):', default: Math.max(0.1, download / 2),
        validate: (v) => (Number.isFinite(v) && v > 0) || 'Harus angka > 0'
      }]);
      return { download, upload };
    }
    const download = Number(speedType);
    return { download, upload: download === 0 ? 0 : Math.max(0.1, Math.round((download / 2) * 10) / 10) };
  }

  applyDeviceLimit(device, download, upload) {
    const prev = this.bw.get(device.mac);
    const limit = {
      identifier: device.mac, download, upload, type: 'device',
      classId: prev?.classId || this.bw.allocClassId(),
      timestamp: new Date().toISOString(), status: 'ACTIVE'
    };
    this.enforce(limit);      // jika gagal, tidak disimpan
    this.bw.set(limit);
  }

  async mainMenu() {
    this.bw.reload();
    this.devices.reload();
    if (daemonPid()) this.stopBackgroundEnforcer();
    this.showBanner();
    this.showActiveLimits();

    const { action } = await inquirer.prompt([{
      type: 'list', name: 'action', message: `${colors.cyan}Pilih menu:${colors.reset}`, pageSize: 15,
      choices: [
        { name: '🔍 Auto-Detect Device', value: 'autodetect' },
        { name: '⚡ Set Bandwidth (Interface)', value: 'limit' },
        { name: '📱 Kelola Device', value: 'device' },
        { name: '🛡️  Enforcer & Service (jaga limit terus-menerus)', value: 'enforcer' },
        { name: '🔄 Hapus Limit', value: 'remove' },
        { name: '📊 Lihat Status', value: 'status' },
        { name: '🚫 Disconnect Semua Device', value: 'disconnect' },
        { name: '🔗 Reconnect Device', value: 'reconnect' },
        { name: '📡 Speed Test', value: 'speedtest' },
        { name: '🔍 Network Interface', value: 'interfaces' },
        { name: '📈 Report', value: 'report' },
        { name: '🧹 Reset Semua (bersihkan tc/iptables)', value: 'reset' },
        { name: '❌ Keluar', value: 'exit' }
      ]
    }]);

    const handlers = {
      autodetect: () => this.autoDetectMenu(), limit: () => this.limitMenu(),
      device: () => this.deviceMenu(), enforcer: () => this.enforcerMenu(),
      remove: () => this.removeMenu(), status: () => this.statusMenu(),
      disconnect: () => this.disconnectAllMenu(), reconnect: () => this.reconnectMenu(),
      speedtest: () => this.speedTestMenu(), interfaces: () => this.interfacesMenu(),
      report: () => this.reportMenu(), reset: () => this.resetMenu()
    };

    if (action === 'exit') return false;
    try {
      await handlers[action]();
    } catch (e) {
      error(e.message);
    }
    return true;
  }

  async scanNetwork({ quiet = false } = {}) {
    const lan = quiet ? this.bw.settings.lanInterface : await this.ensureLanInterface();
    const say = (s) => { if (!quiet) console.log(s); };
    if (!quiet) { this.busy = true; info(`🔍 Memindai jaringan di ${lan} (butuh beberapa detik)...`); }

    try {
      const found = await this.net.scan(lan);
      let added = 0;
      let moved = 0;

      for (const d of found) {
        const ex = this.devices.get(d.mac);
        if (!ex) {
          const name = await this.net.resolveName(d.ip, d.mac);
          const dev = this.devices.upsert(d.mac, name, d.ip);
          added++;
          say(`${colors.green}   ✓ ${name} (${d.ip})${colors.reset}`);
          this.log(`Device baru: ${name} (${d.ip}, ${d.mac})`);
          const pol = this.bw.settings.defaultPolicy;
          if (pol) {
            try {
              this.applyDeviceLimit(dev, pol.download, pol.upload);
              say(`${colors.yellow}     ↳ kebijakan device baru diterapkan${colors.reset}`);
              this.log(`Kebijakan default diterapkan ke ${name}`);
            } catch (e) { this.log(`Gagal menerapkan kebijakan default: ${e.message}`); }
          }
        } else if (ex.ipAddress !== d.ip) {
          // IP berubah (DHCP): pindahkan aturan firewall/tc ke IP baru
          const oldIp = ex.ipAddress;
          this.fw.unblockIp(oldIp, 'lim');
          this.fw.unblockIp(oldIp, 'disc');
          const dev = this.devices.upsert(d.mac, ex.name, d.ip);
          const l = this.bw.get(d.mac);
          if (l) this.enforce(l);
          if (dev.status === 'DISCONNECTED') this.fw.block(dev, 'disc');
          moved++;
          say(`${colors.yellow}   ↻ ${ex.name}: ${oldIp} → ${d.ip}${colors.reset}`);
          this.log(`IP berubah ${ex.name}: ${oldIp} -> ${d.ip}, aturan dipindahkan`);
        }
      }

      if (!quiet) {
        console.log();
        if (found.length === 0) warn('Tidak ada device lain terdeteksi. Pastikan klien terhubung ke interface ini.');
        else success(`${found.length} device aktif, ${added} baru, ${moved} berubah IP.`);
        console.log();
      }
      return this.devices.getConnected();
    } finally {
      if (!quiet) this.busy = false;
    }
  }

  async autoDetectMenu() {
    console.log();
    const devices = await this.scanNetwork();
    if (devices.length > 0) {
      const { limit } = await inquirer.prompt([{
        type: 'confirm', name: 'limit', default: true,
        message: `${colors.cyan}Apakah ingin membatasi device yang terdeteksi?${colors.reset}`
      }]);
      if (limit) await this.limitAllDevicesMenu();
    }
  }

  async limitMenu() {
    console.log();
    const ifaces = this.net.getAllInterfaces();
    if (ifaces.length === 0) { error('Tidak ada interface!'); return; }

    const { name } = await inquirer.prompt([{
      type: 'list', name: 'name', message: `${colors.cyan}Pilih interface:${colors.reset}`,
      choices: ifaces.map((i) => ({ name: `${i.type} ${i.name} (${i.ipv4})`, value: i.name }))
    }]);
    const { download, upload } = await this.askSpeed('Batas total untuk trafik yang tidak punya limit device:');

    // hanya satu limit interface, dan interface itu menjadi interface LAN
    for (const l of this.bw.getAll().filter((x) => x.type === 'interface' && x.identifier !== name)) {
      try { this.release(l); } catch (_) { /* abaikan */ }
      this.bw.remove(l.identifier);
    }
    this.switchLan(name);

    const limit = { identifier: name, download, upload, type: 'interface', timestamp: new Date().toISOString(), status: 'ACTIVE' };
    this.enforce(limit);
    this.bw.set(limit);

    console.log();
    success('Limit di-set!');
    console.log(`${colors.green}   Interface: ${name}${colors.reset}`);
    console.log(download === 0 ? `${colors.red}   Status: 🚫 BLOCKED${colors.reset}` : `${colors.green}   ↓ ${download}Mbps ↑ ${upload}Mbps${colors.reset}`);
    console.log();
  }

  async deviceMenu() {
    console.log();
    const { choice } = await inquirer.prompt([{
      type: 'list', name: 'choice', message: `${colors.cyan}Pilih aksi:${colors.reset}`,
      choices: [
        { name: '🔍 Deteksi Device Baru', value: 'detect' },
        { name: '➕ Tambah Device Manual', value: 'add' },
        { name: '⚡ Batasi Semua Device', value: 'limitAll' },
        { name: '⚡ Batasi 1 Device', value: 'limitOne' },
        { name: '⛔ Disconnect 1 Device', value: 'disconnectOne' },
        { name: '📋 Lihat Semua Device', value: 'list' },
        { name: '🗑️  Hapus Device dari Daftar', value: 'delete' },
        { name: '🔙 Kembali', value: 'back' }
      ]
    }]);
    switch (choice) {
      case 'detect': await this.scanNetwork(); break;
      case 'add': await this.addDeviceMenu(); break;
      case 'limitAll': await this.limitAllDevicesMenu(); break;
      case 'limitOne': await this.limitOneDeviceMenu(); break;
      case 'disconnectOne': await this.disconnectOneMenu(); break;
      case 'list': this.listDevices(); break;
      case 'delete': await this.deleteDeviceMenu(); break;
    }
  }

  async addDeviceMenu() {
    console.log();
    const m = await inquirer.prompt([
      { type: 'input', name: 'name', message: 'Nama device:', default: 'Device' },
      { type: 'input', name: 'ipAddress', message: 'IP Address:', validate: (v) => isIPv4(v.trim()) || 'IP tidak valid' },
      { type: 'input', name: 'mac', message: 'MAC Address (aa:bb:cc:dd:ee:ff):', validate: (v) => isMAC(v.trim()) || 'MAC tidak valid' }
    ]);
    this.devices.upsert(m.mac.trim(), m.name.trim(), m.ipAddress.trim());
    console.log();
    success(`Device ${m.name} ditambahkan!`);
    console.log(`${colors.green}   MAC: ${m.mac.toUpperCase()}${colors.reset}\n`);
  }

  async deleteDeviceMenu() {
    console.log();
    const all = this.devices.getAll();
    if (all.length === 0) { warn('Belum ada device!'); return; }
    const { mac } = await inquirer.prompt([{
      type: 'list', name: 'mac', message: `${colors.cyan}Hapus device:${colors.reset}`,
      choices: all.map((d) => ({ name: `${d.name} (${d.ipAddress})`, value: d.mac }))
    }]);
    const dev = this.devices.get(mac);
    const l = this.bw.get(mac);
    if (l) { try { this.release(l); } catch (_) { /* abaikan */ } this.bw.remove(mac); }
    this.fw.unblock(dev, 'disc');
    this.devices.remove(mac);
    success(`${dev.name} dihapus (beserta limit-nya).`);
  }

  async limitAllDevicesMenu() {
    console.log();
    await this.ensureLanInterface();
    const devices = this.devices.getConnected();
    if (devices.length === 0) { warn('Tidak ada device! Jalankan Auto-Detect dulu.'); return; }

    const { download, upload } = await this.askSpeed('Kecepatan untuk semua device:');
    console.log();
    info('Menerapkan limit...');

    let count = 0;
    for (const d of devices) {
      try {
        this.applyDeviceLimit(d, download, upload);
        count++;
        console.log(download === 0 ? `   ${colors.red}🚫 ${d.name}${colors.reset}` : `   ${colors.green}✓ ${d.name}${colors.reset}`);
      } catch (e) {
        console.log(`   ${colors.red}✗ ${d.name}: ${e.message}${colors.reset}`);
      }
    }
    console.log();
    success(`${count}/${devices.length} device di-limit!`);
    console.log(download === 0 ? `${colors.red}   Status: 🚫 BLOCKED${colors.reset}` : `${colors.green}   ↓ ${download}Mbps ↑ ${upload}Mbps${colors.reset}`);
    console.log();
  }

  async limitOneDeviceMenu() {
    console.log();
    await this.ensureLanInterface();
    const devices = this.devices.getConnected();
    if (devices.length === 0) { warn('Tidak ada device! Jalankan Auto-Detect dulu.'); return; }

    const { mac } = await inquirer.prompt([{
      type: 'list', name: 'mac', message: `${colors.cyan}Pilih device:${colors.reset}`,
      choices: devices.map((d) => ({ name: `${d.name} (${d.ipAddress})`, value: d.mac }))
    }]);
    const { download, upload } = await this.askSpeed('Kecepatan:');
    const device = this.devices.get(mac);
    this.applyDeviceLimit(device, download, upload);

    console.log();
    success('Limit di-set!');
    console.log(`${colors.green}   Device: ${device.name} (${device.ipAddress})${colors.reset}`);
    console.log(download === 0 ? `${colors.red}   Status: 🚫 BLOCKED${colors.reset}` : `${colors.green}   ↓ ${download}Mbps ↑ ${upload}Mbps${colors.reset}`);
    console.log();
  }

  async disconnectOneMenu() {
    console.log();
    await this.ensureLanInterface();
    const devices = this.devices.getConnected();
    if (devices.length === 0) { warn('Tidak ada device!'); return; }
    const { mac } = await inquirer.prompt([{
      type: 'list', name: 'mac', message: `${colors.cyan}Disconnect device:${colors.reset}`,
      choices: devices.map((d) => ({ name: `${d.name} (${d.ipAddress})`, value: d.mac }))
    }]);
    const d = this.devices.get(mac);
    this.fw.block(d, 'disc');
    this.devices.setStatus(mac, 'DISCONNECTED');
    this.kick(d);
    this.applied.delete(`disc:${mac}`);
    success(`${d.name} diputus paksa dan akan terus dijaga.`);
  }

  listDevices() {
    console.log();
    const devices = this.devices.getAll();
    if (devices.length === 0) { warn('Belum ada device!'); return; }
    console.log(`${colors.magenta}${colors.bold}\n📱 Device List:${colors.reset}`);
    devices.forEach((d, i) => {
      const icon = d.status === 'CONNECTED' ? '🟢' : '🔴';
      console.log(`${colors.cyan}   ${i + 1}. ${icon} ${d.name}${colors.reset}`);
      console.log(`${colors.gray}      IP: ${d.ipAddress}${colors.reset}`);
      console.log(`${colors.gray}      MAC: ${d.mac}${colors.reset}`);
      console.log(`${colors.gray}      Status: ${d.status}${colors.reset}\n`);
    });
  }

  async disconnectAllMenu() {
    console.log();
    await this.ensureLanInterface();
    const devices = this.devices.getConnected();
    if (devices.length === 0) { warn('Tidak ada device lain!'); return; }

    console.log(`${colors.magenta}${colors.bold}\nDevice yang akan di-disconnect:${colors.reset}`);
    devices.forEach((d, i) => console.log(`${colors.red}   ${i + 1}. ${d.name} (${d.ipAddress})${colors.reset}`));

    const { sure } = await inquirer.prompt([{
      type: 'confirm', name: 'sure', default: false,
      message: `${colors.red}Disconnect paksa ${devices.length} device?${colors.reset}`
    }]);
    if (!sure) return;

    console.log();
    info('Disconnecting...');
    let count = 0;
    for (const d of devices) {
      try {
        this.fw.block(d, 'disc');
        this.devices.setStatus(d.mac, 'DISCONNECTED');
        this.kick(d);
        count++;
        console.log(`${colors.green}   ✅ ${d.name}${colors.reset}`);
      } catch (e) {
        console.log(`${colors.red}   ✗ ${d.name}: ${e.message}${colors.reset}`);
      }
    }
    console.log();
    success(`${count} device diputus paksa!`);
    console.log();
  }

  async reconnectMenu() {
    console.log();
    const devices = this.devices.getDisconnected();
    if (devices.length === 0) { warn('Tidak ada device yang disconnected!'); return; }

    const { target } = await inquirer.prompt([{
      type: 'list', name: 'target', message: `${colors.cyan}Reconnect device:${colors.reset}`,
      choices: [
        { name: '🔗 Reconnect Semua', value: 'all' },
        ...devices.map((d) => ({ name: `${d.name} (${d.ipAddress})`, value: d.mac }))
      ]
    }]);

    console.log();
    info('Reconnecting...');
    const list = target === 'all' ? devices : [this.devices.get(target)];
    for (const d of list) {
      this.fw.unblock(d, 'disc');
      this.devices.setStatus(d.mac, 'CONNECTED');
      console.log(`${colors.green}   ✅ ${d.name}${colors.reset}`);
    }
    console.log();
    success(`${list.length} device reconnected!\n`);
  }

  async removeMenu() {
    console.log();
    const limits = this.bw.getAll();
    if (limits.length === 0) { warn('Tidak ada limit!'); return; }

    const { identifier } = await inquirer.prompt([{
      type: 'list', name: 'identifier', message: `${colors.cyan}Pilih limit untuk dihapus:${colors.reset}`,
      choices: limits.map((l) => ({ name: this.limitLabel(l), value: l.identifier }))
    }]);
    const { sure } = await inquirer.prompt([{ type: 'confirm', name: 'sure', message: 'Hapus?', default: false }]);
    if (!sure) return;

    this.release(this.bw.get(identifier));
    this.bw.remove(identifier);
    console.log();
    success('Limit dihapus!\n');
  }

  limitLabel(l) {
    const dev = l.type === 'device' ? this.devices.get(l.identifier) : null;
    const name = dev ? `${dev.name} (${dev.ipAddress})` : l.identifier;
    const speed = l.download === 0 ? '🚫 BLOCKED' : `↓${l.download}Mbps ↑${l.upload}Mbps`;
    return `${l.type === 'device' ? '📱' : '🌐'} ${name} [${speed}]`;
  }

  // Mengukur throughput nyata dari counter tc selama `seconds` detik
  async measure(limits, seconds = 2) {
    const lan = this.bw.settings.lanInterface;
    const items = limits
      .filter((l) => l.download !== 0)
      .map((l) => ({ l, minor: l.type === 'interface' ? DEFAULT_CLASS : l.classId }));
    const read = () => items.map((it) => ({
      d: this.tc.classBytes(lan, it.minor), u: this.tc.classBytes(IFB_NAME, it.minor)
    }));
    const a = read();
    await sleep(seconds * 1000);
    const b = read();
    const mbps = (x, y) => (x == null || y == null ? null : ((y - x) * 8) / 1e6 / seconds);
    const out = new Map();
    items.forEach((it, i) => out.set(it.l.identifier, { down: mbps(a[i].d, b[i].d), up: mbps(a[i].u, b[i].u) }));
    return out;
  }

  fmt(v, limit) {
    if (v == null) return 'n/a';
    return `${v.toFixed(2)}Mbps${limit ? ` (${Math.min(100, Math.round((v / limit) * 100))}%)` : ''}`;
  }

  async statusMenu() {
    console.log();
    const limits = this.bw.getAll();
    if (limits.length === 0) { warn('Tidak ada limit!'); return; }

    const { identifier } = await inquirer.prompt([{
      type: 'list', name: 'identifier', message: `${colors.cyan}Pilih untuk lihat status:${colors.reset}`,
      choices: limits.map((l) => ({ name: this.limitLabel(l), value: l.identifier }))
    }]);
    const l = this.bw.get(identifier);

    console.log(`${colors.cyan}${colors.bold}\n📊 Traffic Info:${colors.reset}`);
    console.log(`${colors.gray}   ID: ${l.identifier}${colors.reset}`);
    if (l.download === 0) {
      console.log(`${colors.red}   Status: 🚫 BLOCKED${colors.reset}\n`);
      return;
    }
    info('Mengukur trafik 2 detik...');
    const m = (await this.measure([l])).get(identifier);
    console.log(`${colors.cyan}   Download: limit ${l.download}Mbps, aktual ${this.fmt(m.down, l.download)}${colors.reset}`);
    console.log(`${colors.cyan}   Upload:   limit ${l.upload}Mbps, aktual ${this.fmt(m.up, l.upload)}${colors.reset}\n`);
  }

  async speedTestMenu() {
    console.log();
    info('Speed test koneksi internet mesin ini (Cloudflare)...');
    const r = await this.net.runSpeedTest();
    console.log(`${colors.cyan}${colors.bold}\n⚡ Result:${colors.reset}`);
    console.log(`${colors.green}   ↓ ${r.downloadSpeed.toFixed(1)}Mbps${colors.reset}`);
    console.log(`${colors.green}   ↑ ${r.uploadSpeed.toFixed(1)}Mbps${colors.reset}`);
    console.log(`${colors.yellow}   Ping: ${r.ping.toFixed(0)}ms  Jitter: ${r.jitter.toFixed(1)}ms${colors.reset}\n`);
  }

  async interfacesMenu() {
    console.log();
    const ifaces = this.net.getAllInterfaces();
    if (ifaces.length === 0) { error('Tidak ada interface!'); return; }

    console.log(`${colors.magenta}${colors.bold}\n🔌 Network Interface:${colors.reset}`);
    ifaces.forEach((i, idx) => {
      const lan = i.name === this.bw.settings.lanInterface ? ' [LAN aktif]' : '';
      console.log(`${colors.cyan}   ${idx + 1}. ${i.type}${lan}${colors.reset}`);
      console.log(`${colors.gray}      Name: ${i.name}${colors.reset}`);
      console.log(`${colors.gray}      IP: ${i.ipv4}${colors.reset}`);
      console.log(`${colors.gray}      MAC: ${i.mac}${colors.reset}\n`);
    });

    const { change } = await inquirer.prompt([{
      type: 'confirm', name: 'change', default: false, message: 'Ganti interface LAN?'
    }]);
    if (change) {
      const { name } = await inquirer.prompt([{
        type: 'list', name: 'name', message: 'Pilih interface LAN:',
        choices: ifaces.map((i) => ({ name: `${i.type} ${i.name} (${i.ipv4})`, value: i.name }))
      }]);
      this.switchLan(name);
      success(`Interface LAN: ${name}`);
    }
  }

  async reportMenu() {
    console.log();
    const limits = this.bw.getAll();
    if (limits.length === 0) { warn('Tidak ada limit!'); return; }

    info('Mengukur trafik 2 detik...');
    const m = await this.measure(limits);
    const blocked = limits.filter((l) => l.download === 0).length;

    console.log(`${colors.magenta}${colors.bold}\n📊 Report:${colors.reset}`);
    console.log(`${colors.gray}   Total Limits: ${limits.length}${colors.reset}`);
    console.log(`${colors.red}   Blocked: ${blocked}${colors.reset}`);
    console.log(`${colors.red}   Disconnected: ${this.devices.getDisconnected().length}${colors.reset}\n`);

    limits.forEach((l, i) => {
      console.log(`${colors.cyan}   ${i + 1}. ${this.limitLabel(l)}${colors.reset}`);
      const t = m.get(l.identifier);
      if (t) console.log(`${colors.gray}      Aktual ↓ ${this.fmt(t.down)}  ↑ ${this.fmt(t.up)}${colors.reset}`);
      console.log();
    });
  }

  async enforcerMenu() {
    console.log();
    const { choice } = await inquirer.prompt([{
      type: 'list', name: 'choice', message: `${colors.cyan}Enforcer & Service:${colors.reset}`,
      choices: [
        { name: '📟 Status enforcer', value: 'status' },
        { name: '📥 Install service systemd (permanen, auto-start saat boot)', value: 'install' },
        { name: '📤 Uninstall service', value: 'uninstall' },
        { name: '▶️  Jalankan enforcer di terminal ini (log live, Ctrl+C untuk berhenti)', value: 'foreground' },
        { name: '🆕 Kebijakan untuk device BARU (otomatis limit/blokir)', value: 'policy' },
        { name: `🌐 Matikan IPv6 device yang dilimit: ${this.bw.settings.blockIPv6 ? 'AKTIF' : 'NONAKTIF'} (ubah)`, value: 'ipv6' },
        { name: '🔙 Kembali', value: 'back' }
      ]
    }]);

    if (choice === 'status') {
      const svc = (tryRun('systemctl', ['is-active', SERVICE_NAME]) || 'tidak terpasang').trim();
      console.log(`\n   ${this.enforcerStatusText()}`);
      console.log(`${colors.gray}   Service systemd: ${svc}`);
      console.log(`   Verifikasi tiap ${CHECK_SECONDS}s, scan tiap ${SCAN_SECONDS}s${colors.reset}\n`);
    } else if (choice === 'install') {
      this.stopBackgroundEnforcer();
      this.installService();
      success('Service terpasang & berjalan. Limit akan dijaga terus, termasuk setelah reboot.');
      info(`Log: journalctl -u ${SERVICE_NAME} -f`);
    } else if (choice === 'uninstall') {
      this.uninstallService();
      success('Service dihapus (aturan yang sudah aktif tetap ada sampai di-reset/reboot).');
      this.startBackgroundEnforcer();
    } else if (choice === 'foreground') {
      this.stopBackgroundEnforcer();
      info('Enforcer berjalan. Tekan Ctrl+C untuk berhenti.\n');
      await this.runDaemon();
    } else if (choice === 'policy') {
      const { mode } = await inquirer.prompt([{
        type: 'list', name: 'mode', message: 'Device baru yang terdeteksi akan:',
        choices: [
          { name: '➖ Dibiarkan (tanpa kebijakan)', value: 'none' },
          { name: '⚡ Otomatis dilimit', value: 'limit' },
          { name: '🚫 Otomatis DIBLOKIR (whitelist: aktifkan manual per device)', value: 'block' }
        ]
      }]);
      if (mode === 'none') this.bw.settings.defaultPolicy = null;
      else if (mode === 'block') this.bw.settings.defaultPolicy = { download: 0, upload: 0 };
      else {
        const s = await this.askSpeed('Kecepatan untuk device baru:');
        this.bw.settings.defaultPolicy = { download: s.download, upload: s.upload };
      }
      this.bw.save();
      success('Kebijakan device baru disimpan.');
    } else if (choice === 'ipv6') {
      this.bw.settings.blockIPv6 = !this.bw.settings.blockIPv6;
      this.bw.save();
      success(`Matikan IPv6 untuk device yang dilimit: ${this.bw.settings.blockIPv6 ? 'AKTIF' : 'NONAKTIF'}`);
    }
  }

  async resetMenu() {
    console.log();
    if (daemonPid() || (tryRun('systemctl', ['is-active', SERVICE_NAME]) || '').trim() === 'active') {
      warn('Daemon/service masih aktif. Matikan dulu (menu Enforcer -> Uninstall) agar tidak diterapkan ulang.');
    }
    const { sure } = await inquirer.prompt([{
      type: 'confirm', name: 'sure', default: false,
      message: `${colors.red}Hapus SEMUA aturan tc/iptables dan limit tersimpan?${colors.reset}`
    }]);
    if (!sure) return;
    this.resetAll();
    this.bw.limits.clear();
    this.bw.settings.nextClassId = FIRST_CLASS;
    this.bw.save();
    for (const d of this.devices.getAll()) this.devices.setStatus(d.mac, 'CONNECTED');
    success('Semua aturan dibersihkan.\n');
  }

  async askContinue() {
    const { cont } = await inquirer.prompt([{
      type: 'confirm', name: 'cont', default: true,
      message: `${colors.yellow}Kembali ke menu?${colors.reset}`
    }]);
    return cont;
  }

  async start() {
    this.preflight();
    if (!this.hardProblem() && this.bw.settings.lanInterface) {
      try { this.syncAll(); } catch (e) { warn(`Gagal menerapkan limit tersimpan: ${e.message}`); }
    }
    this.startBackgroundEnforcer();

    while (true) {
      const keep = await this.mainMenu();
      if (!keep || !(await this.askContinue())) break;
    }

    console.log(`${colors.yellow}${colors.bold}\n👋 Selamat tinggal!\n${colors.reset}`);
    if (!daemonPid()) {
      console.log(`${colors.gray}Catatan: aturan yang sudah terpasang tetap aktif di kernel, tetapi tanpa daemon/service`);
      console.log(`tidak ada yang memulihkannya jika hilang. Pasang service lewat menu Enforcer & Service.${colors.reset}\n`);
    }
  }
}

const app = new App();
if (DAEMON) {
  app.runDaemon().catch((err) => {
    console.error(`Fatal: ${err.message}`);
    process.exit(1);
  });
} else {
  process.on('SIGINT', () => { console.log(); process.exit(0); });
  app.start().then(() => process.exit(0)).catch((err) => {
    error(`Error: ${err.message}`);
    process.exit(1);
  });
}
