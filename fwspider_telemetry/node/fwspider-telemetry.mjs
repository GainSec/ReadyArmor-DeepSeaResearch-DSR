// fwspider-telemetry.mjs — Node emitter for the Firmware Spider event schema (fwspider.event.v1).
//
// Byte-compatible on-disk protocol with the Python package fwspider_telemetry:
//   * same event-schema.json taxonomy and redaction-rules.json (loaded from this module's directory)
//   * same mkdir(.lock)+owner.json inter-process lock, per-run state.json seq reservation,
//     events/current.jsonl + human/current.log, rotation into seg-NNNNNN.jsonl[.gz] with a hash-chained
//     events/INDEX.jsonl, runs/<run_id>/manifest.json, runs/<run_id>/artifacts/art_*.json envelopes.
// Synchronous fs calls keep per-process ordering exact. Stdlib only.
import { createHash, randomUUID } from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import zlib from 'node:zlib';
import { fileURLToPath } from 'node:url';

const HERE = path.dirname(fileURLToPath(import.meta.url));
// shared files sit next to this module when vendored, or one level up inside the Python package
const shared = (name) => [path.join(HERE, name), path.join(HERE, '..', name)].find((p) => fs.existsSync(p));
export const SCHEMA = JSON.parse(fs.readFileSync(shared('event-schema.json'), 'utf8'));
export const RULES = JSON.parse(fs.readFileSync(shared('redaction-rules.json'), 'utf8'));
export const SCHEMA_VERSION = SCHEMA.schema_version;
export const TAXONOMY = SCHEMA.event_types;
const LEVELS = SCHEMA.levels;
const REDACTED = RULES.replacement;
const ID_FIELDS = ['campaign_id', 'job_id', 'model_call_id', 'tool_call_id', 'artifact_id', 'finding_id'];
const ENV_IDS = { campaign_id: 'FIRMWARE_SPIDER_CAMPAIGN_ID', job_id: 'FIRMWARE_SPIDER_JOB_ID',
  model_call_id: 'FIRMWARE_SPIDER_MODEL_CALL_ID', tool_call_id: 'FIRMWARE_SPIDER_TOOL_CALL_ID' };
const KEY_ORDER = ['schema_version', 'event_id', 'ts', 'monotonic_ns', 'seq', 'level', 'event_type', 'component', 'host',
  'pid', 'run_id', 'process_id', 'parent_event_id', 'campaign_id', 'job_id', 'model_call_id', 'tool_call_id',
  'artifact_id', 'finding_id', 'message', 'data', 'log_artifacts', 'redaction', 'debug'];
const PROFILES = {
  local: { platform: 'darwin', home: '/Users/dsr/firmware-spider', log_dir: '/Users/dsr/firmware-spider/var/log' },
  spark: { platform: 'linux', home: '/home/dsr/firmware-spider', log_dir: '/home/dsr/firmware-spider/logs' },
};
const DIR_MODE = 0o700;
const FILE_MODE = 0o600;

export class ObservabilityError extends Error { constructor(m, opts) { super(m, opts); this.name = 'ObservabilityError'; } }

const sha256 = (data) => createHash('sha256').update(data).digest('hex');
const newId = (prefix) => `${prefix}_${randomUUID().replace(/-/g, '')}`;
const truthy = (v, d) => (v === undefined || v === '' ? d : ['1', 'true', 'yes', 'on'].includes(String(v).trim().toLowerCase()));
const isDir = (p) => { try { return fs.statSync(p).isDirectory(); } catch { return false; } };
const sleepSync = (ms) => Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, ms);

export function utcTs() {
  // Node clocks give milliseconds; the schema's microsecond field is zero-padded (ordering uses seq).
  return new Date().toISOString().replace(/\.(\d{3})Z$/, '.$1000Z');
}

export function newRunId() {
  const d = new Date().toISOString().replace(/[-:]/g, '').replace(/\.\d{3}Z$/, 'Z');
  return `run_${d}_${randomUUID().replace(/-/g, '').slice(0, 12)}`;
}

// Python json.dumps(obj, sort_keys=True) (default separators, ensure_ascii=True) — used for the index hash chain.
export function pyDumps(v) {
  if (v === null || v === undefined) return 'null';
  if (typeof v === 'boolean') return v ? 'true' : 'false';
  if (typeof v === 'number') return Number.isInteger(v) ? String(v) : JSON.stringify(v);
  if (typeof v === 'string') return JSON.stringify(v).replace(/[\u007f-￿]/g, (c) => '\\u' + c.charCodeAt(0).toString(16).padStart(4, '0'));
  if (Array.isArray(v)) return '[' + v.map(pyDumps).join(', ') + ']';
  return '{' + Object.keys(v).sort().map((k) => `${pyDumps(k)}: ${pyDumps(v[k])}`).join(', ') + '}';
}

export function resolveLogDir(explicit, env = process.env, platform = process.platform, exists = isDir) {
  if (explicit) return [explicit, 'argument', null];
  if (env.FIRMWARE_SPIDER_LOG_DIR) return [env.FIRMWARE_SPIDER_LOG_DIR, 'env:FIRMWARE_SPIDER_LOG_DIR', env.FIRMWARE_SPIDER_PROFILE || null];
  const prof = env.FIRMWARE_SPIDER_PROFILE;
  if (prof) {
    if (!PROFILES[prof]) throw new ObservabilityError(`FIRMWARE_SPIDER_PROFILE must be one of local,spark, got ${prof}`);
    return [PROFILES[prof].log_dir, `profile:${prof}(env)`, prof];
  }
  for (const [name, spec] of Object.entries(PROFILES)) {
    if (platform.startsWith(spec.platform) && exists(spec.home)) return [spec.log_dir, `profile:${name}(detected)`, name];
  }
  if (env.FIRMWARE_SPIDER_HOME) return [path.join(env.FIRMWARE_SPIDER_HOME, 'var', 'log'), 'env:FIRMWARE_SPIDER_HOME', null];
  const base = env.XDG_STATE_HOME || path.join(os.homedir(), '.local', 'state');
  return [path.join(base, 'firmware-spider', 'log'), 'fallback', null];
}

// ---------------------------------------------------------------- redaction
function luhnOk(text) {
  const d = [...text].filter((c) => c >= '0' && c <= '9').map(Number);
  if (d.length < 13 || d.length > 19) return false;
  let t = 0;
  d.reverse().forEach((x, i) => { if (i % 2) { x *= 2; if (x > 9) x -= 9; } t += x; });
  return t % 10 === 0;
}

class Report {
  constructor() { this.count = 0; this.rules = new Set(); this.paths = []; }
  hit(rule, p) { this.count++; this.rules.add(rule); if (this.paths.length < 50 && !this.paths.includes(p)) this.paths.push(p); }
  asDict() { return this.count ? { count: this.count, rules: [...this.rules].sort(), paths: this.paths } : null; }
}

export class Redactor {
  constructor(extra = []) {
    this.rules = RULES.string_rules.map((r) => ({ name: r.name, re: new RegExp(r.pattern, 'g' + (r.flags || '')), keep: r.keep || [], luhn: !!r.luhn }));
    extra.forEach((p, i) => this.rules.push({ name: `custom_${i}`, re: new RegExp(p, 'g'), keep: [], luhn: false }));
    this.keyRe = new RegExp(RULES.sensitive_key_pattern);
    this.nonSecret = new Set(RULES.non_secret_keys);
    this.nonSecretExact = new Set(RULES.case_sensitive_non_secret_keys || []);
  }
  sensitiveKey(key) {
    if (this.nonSecretExact.has(String(key))) return false;
    const k = String(key).trim().replace(/^-+/, '').toLowerCase().replace(/[-. ]/g, '_');
    return !this.nonSecret.has(k) && this.keyRe.test(k);
  }
  text(s, rep, p = '$') {
    for (const r of this.rules) {
      s = s.replace(r.re, (...m) => {
        const whole = m[0];
        if (r.luhn && !luhnOk(whole)) return whole;
        rep?.hit(r.name, p);
        if (!r.keep.length) return REDACTED;
        return (m[r.keep[0]] || '') + REDACTED + r.keep.slice(1).map((g) => m[g] || '').join('');
      });
    }
    return s;
  }
  value(v, rep, p = '$') {
    if (typeof v === 'string') return this.text(v, rep, p);
    if (Buffer.isBuffer(v)) return { _bytes: true, length: v.length, sha256: sha256(v) };
    if (Array.isArray(v)) return v.map((x, i) => this.value(x, rep, `${p}[${i}]`));
    if (v && typeof v === 'object') {
      if (v instanceof Error) return this.text(String(v), rep, p);
      const out = {};
      for (const [k, x] of Object.entries(v)) {
        const sub = `${p}.${k}`;
        const empty = x === null || x === undefined || x === '' || (Array.isArray(x) && !x.length) || (typeof x === 'object' && x && !Object.keys(x).length);
        if (this.sensitiveKey(k) && !empty) { rep?.hit('sensitive_key', sub); out[k] = REDACTED; } else out[k] = this.value(x, rep, sub);
      }
      return out;
    }
    if (v === undefined) return null;
    if (typeof v === 'bigint') return Number(v);
    return v;
  }
  argv(argv, rep) {
    const out = [];
    let next = false;
    argv.map(String).forEach((a, i) => {
      const p = `$.argv[${i}]`;
      if (next) { next = false; rep?.hit('sensitive_flag_value', p); out.push(REDACTED); return; }
      if (a.startsWith('-') && a.includes('=')) {
        const [flag, ...rest] = a.split('=');
        if (this.sensitiveKey(flag) && rest.join('=')) { rep?.hit('sensitive_flag_value', p); out.push(`${flag}=${REDACTED}`); return; }
      } else if (a.startsWith('-') && this.sensitiveKey(a)) next = true;
      out.push(this.text(a, rep, p));
    });
    return out;
  }
  envSummary(env = process.env, debug = false) {
    const allow = new Set(RULES.env_allowlist);
    const h = createHash('sha256');
    const keys = Object.keys(env).sort();
    for (const k of keys) h.update(Buffer.concat([Buffer.from(k + '\0'), createHash('sha256').update(String(env[k])).digest(), Buffer.from('\n')]));
    const out = { allowlisted: Object.fromEntries(keys.filter((k) => allow.has(k)).map((k) => [k, this.text(String(env[k]))])),
      digest: 'sha256:' + h.digest('hex'), count: keys.length };
    if (debug) out.names_sha256 = sha256(keys.join('\n'));
    return out;
  }
}

export function exceptionData(err, retry = null) {
  const chain = [];
  const seen = new Set();
  let cur = err; let relation = 'raised';
  while (cur && !seen.has(cur)) {
    seen.add(cur);
    chain.push({ relation, type: `node.${cur?.name || cur?.constructor?.name || typeof cur}`, message: String(cur?.message ?? cur) });
    cur = cur?.cause; relation = 'cause';
  }
  return { type: chain[0].type, message: String(err?.message ?? err), stack: String(err?.stack || err).split('\n'), cause_chain: chain, retry };
}

const SNIFF = [[0, '7f454c46', 'elf'], [0, '1f8b', 'gzip'], [0, '504b0304', 'zip'], [0, '68737173', 'squashfs-le'],
  [0, '73717368', 'squashfs-be'], [0, '55424923', 'ubi'], [0, '27051956', 'uimage'], [0, '48445230', 'trx'],
  [0, 'fd377a585a00', 'xz'], [0, '425a68', 'bzip2'], [0, '4d5a', 'pe'], [0, 'd00dfeed', 'dtb'], [257, '7573746172', 'tar']];
function sniff(head) {
  for (const [off, hex, kind] of SNIFF) if (head.subarray(off, off + hex.length / 2).toString('hex') === hex) return kind;
  return head.length && [...head.subarray(0, 512)].every((b) => (b >= 32 && b < 127) || [9, 10, 13].includes(b)) ? 'text' : 'data';
}

// ---------------------------------------------------------------- sink
function orderedLine(ev) {
  const out = {};
  for (const k of KEY_ORDER) if (ev[k] !== undefined && ev[k] !== null) out[k] = ev[k];
  return JSON.stringify(out) + '\n';
}

export function formatHuman(ev, width = 400) {
  const label = (k) => (k === 'model_call_id' ? 'model' : k.split('_')[0]);
  const ids = ['campaign_id', 'job_id', 'model_call_id', 'tool_call_id', 'finding_id', 'artifact_id'].filter((k) => ev[k]).map((k) => `${label(k)}=${ev[k]}`).join(' ');
  const sortDeep = (v) => (Array.isArray(v) ? v.map(sortDeep) : v && typeof v === 'object' ? Object.fromEntries(Object.keys(v).sort().map((k) => [k, sortDeep(v[k])])) : v);
  let data = JSON.stringify(sortDeep(ev.data || {}));
  if (data.length > width) data = `${data.slice(0, width)}…(+${data.length - width} chars; full data in event ${ev.event_id})`;
  const red = ev.redaction ? ` redactions=${ev.redaction.count}` : '';
  const msg = ev.message ? ` ${ev.message}` : '';
  return `${ev.ts} ${String(ev.level).toUpperCase().padEnd(8)} ${ev.component} run=${ev.run_id} seq=${ev.seq} ${ev.event_type}${ids ? ' ' + ids : ''}${msg}${red} ${data}\n`;
}

class LogDir {
  constructor(root, cfg) { Object.assign(this, { root, ...cfg }); this.held = 0; this.host = os.hostname(); }
  p(...a) { return path.join(this.root, ...a); }
  mkdir(d) {
    const missing = [];
    let cur = d;
    while (!isDir(cur)) { missing.push(cur); cur = path.dirname(cur); }
    for (const m of missing.reverse()) { try { fs.mkdirSync(m, { mode: DIR_MODE }); } catch (e) { if (e.code !== 'EEXIST') throw e; } fs.chmodSync(m, DIR_MODE); }
  }
  ensure() { for (const d of [this.root, this.p('events'), this.p('human'), this.p('runs')]) this.mkdir(d); }
  writeNew(file, data) {
    const tmp = path.join(path.dirname(file), `.${path.basename(file)}.${process.pid}.${randomUUID().slice(0, 8)}.tmp`);
    const fd = fs.openSync(tmp, fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_EXCL, FILE_MODE);
    try { fs.writeSync(fd, data); if (this.fsync) fs.fsyncSync(fd); } finally { fs.closeSync(fd); }
    fs.renameSync(tmp, file);
  }
  append(file, data) {
    const buf = Buffer.from(data, 'utf8');
    const fd = fs.openSync(file, fs.constants.O_WRONLY | fs.constants.O_APPEND | fs.constants.O_CREAT, FILE_MODE);
    try {
      const n = fs.writeSync(fd, buf);
      if (n !== buf.length) throw new Error(`short write to ${file}: ${n} of ${buf.length} bytes`);
      if (this.fsync) fs.fsyncSync(fd);
    } finally { fs.closeSync(fd); }
  }
  withLock(fn) {
    if (this.held) { this.held++; try { return fn(); } finally { this.held--; } }
    this.acquire(); this.held = 1;
    try { return fn(); } finally { this.held = 0; this.release(); }
  }
  acquire() {
    const lock = this.p('.lock');
    const deadline = Date.now() + this.lock_timeout_s * 1000;
    let delay = 1;
    for (;;) {
      try {
        fs.mkdirSync(lock, { mode: DIR_MODE });
        const fd = fs.openSync(path.join(lock, 'owner.json'), 'w', FILE_MODE);
        try { fs.writeSync(fd, JSON.stringify({ host: this.host, pid: process.pid, ts: Date.now() / 1000, lang: 'node' })); } finally { fs.closeSync(fd); }
        return;
      } catch (e) {
        if (e.code === 'ENOENT') { this.mkdir(this.root); continue; }
        if (e.code !== 'EEXIST') throw e;
        this.breakStale(lock);
      }
      if (Date.now() > deadline) throw new Error(`could not acquire telemetry lock ${lock} within ${this.lock_timeout_s}s`);
      sleepSync(delay); delay = Math.min(delay * 2, 20);
    }
  }
  breakStale(lock) {
    let st; try { st = fs.statSync(lock); } catch { return; }
    let owner = null; try { owner = JSON.parse(fs.readFileSync(path.join(lock, 'owner.json'), 'utf8')); } catch { /* being written */ }
    const age = Date.now() / 1000 - st.mtimeMs / 1000;
    let stale = false;
    if (owner && owner.host === this.host && Number.isInteger(owner.pid)) {
      try { process.kill(owner.pid, 0); } catch (e) { if (e.code === 'ESRCH') stale = true; }
    }
    if (age > this.stale_lock_s || (!owner && age > 5)) stale = true;
    if (stale) {
      const grave = path.join(this.root, `.lock.stale-${randomUUID().slice(0, 8)}`);
      try { fs.renameSync(lock, grave); } catch { return; }
      fs.rmSync(grave, { recursive: true, force: true });
    }
  }
  release() {
    const lock = this.p('.lock');
    try { fs.unlinkSync(path.join(lock, 'owner.json')); } catch { /* gone */ }
    fs.rmdirSync(lock);
  }
  readState(runId) { try { return JSON.parse(fs.readFileSync(this.p('runs', runId, 'state.json'), 'utf8')); } catch (e) { if (e.code === 'ENOENT') return {}; throw e; } }
  activeSegment() {
    const f = this.p('events', 'ACTIVE');
    try { return parseInt(fs.readFileSync(f, 'utf8').trim(), 10); } catch (e) { if (e.code !== 'ENOENT') throw e; this.writeNew(f, '1\n'); return 1; }
  }
  writeEvent(ev, onRotate) {
    return this.withLock(() => {
      this.ensure();
      const rd = this.p('runs', ev.run_id);
      this.mkdir(rd);
      const st = this.readState(ev.run_id);
      const seg = this.activeSegment();
      st.seq = (st.seq || 0) + 1;
      st.events = (st.events || 0) + 1;
      st.segments = st.segments || [];
      if (!st.segments.includes(seg)) st.segments.push(seg);
      st.first_ts = st.first_ts || ev.ts; st.last_ts = ev.ts; st.run_id = ev.run_id;
      this.writeNew(path.join(rd, 'state.json'), pyDumps(st));  // reserve seq before append
      ev.seq = st.seq;
      this.append(this.p('events', 'current.jsonl'), orderedLine(ev));
      this.append(this.p('human', 'current.log'), formatHuman(ev));
      if (fs.statSync(this.p('events', 'current.jsonl')).size >= this.rotate_bytes) { const r = this.rotate(); if (onRotate) onRotate(r); }
      return ev;
    });
  }
  seal(src, dstBase) {
    const data = fs.readFileSync(src);
    const info = { uncompressed_sha256: sha256(data), uncompressed_bytes: data.length };
    if (this.compress) {
      const gz = zlib.gzipSync(data);
      if (!zlib.gunzipSync(gz).equals(data)) throw new Error(`compression round-trip failed for ${src}`);
      const dst = dstBase + '.gz';
      this.writeNew(dst, gz); fs.unlinkSync(src);
      Object.assign(info, { file: path.basename(dst), sha256: sha256(gz), bytes: gz.length, compressed: true });
    } else {
      fs.renameSync(src, dstBase); fs.chmodSync(dstBase, FILE_MODE);
      Object.assign(info, { file: path.basename(dstBase), sha256: info.uncompressed_sha256, bytes: data.length, compressed: false });
    }
    return info;
  }
  indexEntries() { try { return fs.readFileSync(this.p('events', 'INDEX.jsonl'), 'utf8').split('\n').filter((l) => l.trim()).map((l) => JSON.parse(l)); } catch (e) { if (e.code === 'ENOENT') return []; throw e; } }
  appendIndex(entry) {
    const prev = this.indexEntries();
    entry.prev_entry_sha256 = prev.length ? prev[prev.length - 1].entry_sha256 : '0'.repeat(64);
    const body = { ...entry }; delete body.entry_sha256;
    entry.entry_sha256 = sha256(pyDumps(body));
    this.append(this.p('events', 'INDEX.jsonl'), pyDumps(entry) + '\n');
    return entry;
  }
  rotate() {
    return this.withLock(() => {
      const seg = this.activeSegment();
      const cur = this.p('events', 'current.jsonl');
      if (!fs.existsSync(cur) || fs.statSync(cur).size === 0) return {};
      const runs = {}; let events = 0; let firstTs = null; let lastTs = null;
      for (const ln of fs.readFileSync(cur, 'utf8').split('\n')) {
        if (!ln.trim()) continue;
        const ev = JSON.parse(ln); events++;
        const r = runs[ev.run_id] || (runs[ev.run_id] = [ev.seq, ev.seq]);
        r[0] = Math.min(r[0], ev.seq); r[1] = Math.max(r[1], ev.seq);
        firstTs = firstTs || ev.ts; lastTs = ev.ts;
      }
      const name = `seg-${String(seg).padStart(6, '0')}`;
      const info = this.seal(cur, this.p('events', `${name}.jsonl`));
      const hc = this.p('human', 'current.log');
      const human = fs.existsSync(hc) ? this.seal(hc, this.p('human', `${name}.log`)) : null;
      const entry = this.appendIndex({ schema_version: SCHEMA.segment_index.schema_version, segment: seg, name, ...info, events, runs,
        first_ts: firstTs, last_ts: lastTs, status: 'present',
        human: human ? { file: human.file, sha256: human.sha256, bytes: human.bytes, uncompressed_sha256: human.uncompressed_sha256 } : null,
        closed_at: new Date().toISOString().replace(/\.\d{3}Z$/, 'Z') });
      this.writeNew(this.p('events', 'ACTIVE'), `${seg + 1}\n`);
      return { closed: entry, deleted: this.applyRetention() };
    });
  }
  applyRetention() {
    const latest = new Map();
    for (const e of this.indexEntries()) latest.set(e.segment, e);
    const present = [...latest.values()].filter((e) => e.status === 'present').sort((a, b) => a.segment - b.segment);
    let doomed = [];
    if (this.retention_segments != null && present.length > this.retention_segments) doomed = present.slice(0, present.length - this.retention_segments);
    if (this.retention_days != null) {
      const cutoff = Date.now() - this.retention_days * 86400000;
      for (const e of present) { try { if (fs.statSync(this.p('events', e.file)).mtimeMs < cutoff && !doomed.includes(e)) doomed.push(e); } catch { /* missing */ } }
    }
    return doomed.map((e) => {
      for (const f of [this.p('events', e.file), e.human ? this.p('human', e.human.file) : null]) if (f) fs.rmSync(f, { force: true });
      const tomb = { ...e }; delete tomb.entry_sha256; delete tomb.prev_entry_sha256;
      Object.assign(tomb, { status: 'deleted', deleted_at: new Date().toISOString().replace(/\.\d{3}Z$/, 'Z'), reason: 'retention' });
      return this.appendIndex(tomb);
    });
  }
  writeArtifact(runId, ref, env) {
    const d = this.p('runs', runId, 'artifacts');
    this.mkdir(d);
    const f = path.join(d, `${ref}.json`);
    this.writeNew(f, JSON.stringify(env) + '\n');
    return f;
  }
  updateManifest(runId, mutate) {
    return this.withLock(() => {
      this.ensure();
      const rd = this.p('runs', runId); this.mkdir(rd);
      const f = path.join(rd, 'manifest.json');
      const now = new Date().toISOString().replace(/\.\d{3}Z$/, 'Z');
      let m;
      try { m = JSON.parse(fs.readFileSync(f, 'utf8')); } catch (e) {
        if (e.code !== 'ENOENT') throw e;
        m = { schema_version: SCHEMA.run_manifest.schema_version, run_id: runId, created_at: now, updated_at: now, status: 'running',
          processes: [], segments: [], events: {}, inputs: [], outputs: [], components: {}, config_digests: {}, models: [], telemetry_failures: 0 };
      }
      mutate(m);
      const st = this.readState(runId);
      m.segments = (st.segments || []).map((s) => `seg-${String(s).padStart(6, '0')}`);
      m.events = { count: st.events || 0, last_seq: st.seq || 0, first_ts: st.first_ts || null, last_ts: st.last_ts || null };
      m.updated_at = now;
      const procs = m.processes || [];
      if (procs.some((p) => p.ended_at == null)) m.status = 'running';
      else if (procs.some((p) => p.status === 'crashed')) m.status = 'crashed';
      else if (procs.some((p) => p.exit_code !== 0 && p.exit_code != null)) m.status = 'completed_with_errors';
      else if (procs.length) m.status = 'completed';
      if (m.closed_status) m.status = m.closed_status;
      this.writeNew(f, JSON.stringify(m, null, 1) + '\n');
      return m;
    });
  }
}

// ---------------------------------------------------------------- emitter
export function configFromEnv(env = process.env, overrides = {}) {
  const [logDir, source, profile] = resolveLogDir(overrides.log_dir, env);
  const intv = (v, d) => (v === undefined || v === '' ? d : parseInt(v, 10));
  const cfg = {
    log_dir: logDir, log_dir_source: source, profile,
    policy: env.FIRMWARE_SPIDER_TELEMETRY_POLICY || 'strict', debug: truthy(env.FIRMWARE_SPIDER_DEBUG, false),
    log_bodies: truthy(env.FIRMWARE_SPIDER_LOG_BODIES, true), max_artifact_bytes: intv(env.FIRMWARE_SPIDER_MAX_ARTIFACT_BYTES, 256 * 1024),
    max_inline_bytes: 16 * 1024, rotate_bytes: intv(env.FIRMWARE_SPIDER_LOG_ROTATE_BYTES, 64 * 1024 * 1024),
    retention_segments: env.FIRMWARE_SPIDER_LOG_RETENTION_SEGMENTS ? intv(env.FIRMWARE_SPIDER_LOG_RETENTION_SEGMENTS) : null,
    retention_days: env.FIRMWARE_SPIDER_LOG_RETENTION_DAYS ? Number(env.FIRMWARE_SPIDER_LOG_RETENTION_DAYS) : null,
    compress: truthy(env.FIRMWARE_SPIDER_LOG_COMPRESS, true), fsync: truthy(env.FIRMWARE_SPIDER_LOG_FSYNC, false),
    lock_timeout_s: 30, stale_lock_s: 120,
    deadletter_dir: env.FIRMWARE_SPIDER_DEADLETTER_DIR || path.join(os.tmpdir(), `fwspider-deadletter-${process.getuid?.() ?? 'x'}`),
    extra_redact_patterns: [],
    ...overrides,
  };
  if (!['strict', 'degrade'].includes(cfg.policy)) throw new ObservabilityError(`telemetry policy must be strict or degrade, got ${cfg.policy}`);
  return cfg;
}

export class Telemetry {
  constructor(component, { config, runId, version, env = process.env } = {}) {
    this.component = component;
    this.config = config || configFromEnv(env);
    this.redactor = new Redactor(this.config.extra_redact_patterns || []);
    this.sink = new LogDir(this.config.log_dir, this.config);
    this.runId = runId || env.FIRMWARE_SPIDER_RUN_ID || newRunId();
    this.joinedRun = !runId && !!env.FIRMWARE_SPIDER_RUN_ID;
    this.processId = newId('proc');
    this.host = os.hostname();
    this.pid = process.pid;
    this.version = version || null;
    this.parentEventId = env.FIRMWARE_SPIDER_PARENT_EVENT_ID || null;
    this.baseIds = Object.fromEntries(Object.entries(ENV_IDS).filter(([, v]) => env[v]).map(([k, v]) => [k, env[v]]));
    this.ctx = {};
    this.failures = 0;
    this.started = false; this.ended = false;
    this.t0 = process.hrtime.bigint();
    this.deadletterPath = path.join(this.config.deadletter_dir, `deadletter-${this.host}-${this.pid}-${this.processId.slice(-8)}.jsonl`);
  }

  bind(ids, fn) { const prev = this.ctx; this.ctx = { ...prev, ...Object.fromEntries(Object.entries(ids).filter(([, v]) => v != null)) }; try { return fn(); } finally { this.ctx = prev; } }
  async bindAsync(ids, fn) { const prev = this.ctx; this.ctx = { ...prev, ...Object.fromEntries(Object.entries(ids).filter(([, v]) => v != null)) }; try { return await fn(); } finally { this.ctx = prev; } }
  context() { return { ...this.baseIds, ...this.ctx }; }

  emit(eventType, data = {}, { level, message = '', component, critical = false, parentEventId, ids = {} } = {}) {
    const spec = TAXONOMY[eventType];
    if (!spec) throw new Error(`unknown telemetry event_type ${eventType}; add it to event-schema.json`);
    const unknown = Object.keys(ids).filter((k) => !ID_FIELDS.includes(k));
    if (unknown.length) throw new Error(`unknown correlation fields ${unknown}`);
    const lvl = level || spec.level;
    if (!LEVELS.includes(lvl)) throw new Error(`unknown level ${lvl}`);
    if (lvl === 'debug' && !this.config.debug) return null;
    if (!this.started && !['process.start', 'process.resume', 'run.start'].includes(eventType)) this.startProcess();
    let ev = null;
    try {
      ev = this.build(eventType, data, lvl, message, component, parentEventId, ids);
      return this.sink.writeEvent(ev, (r) => this.afterRotate(r));
    } catch (e) {
      if (e instanceof ObservabilityError) throw e;
      this.failure(e, ev, eventType, critical);
      return null;
    }
  }

  build(eventType, data, level, message, component, parentEventId, ids) {
    const rep = new Report();
    let d = this.redactor.value(data || {}, rep, '$.data');
    const msg = this.redactor.text(message || '', rep, '$.message');
    const arts = [];
    const walk = (v, depth) => {
      if (depth > 8 || !v || typeof v !== 'object') return;
      if (!Array.isArray(v) && String(v.artifact_ref || '').startsWith('art_')) arts.push(v.artifact_ref);
      for (const x of Array.isArray(v) ? v : Object.values(v)) walk(x, depth + 1);
    };
    walk(d, 0);
    if (Buffer.byteLength(JSON.stringify(d)) > this.config.max_inline_bytes) {
      const ref = this.artifact('event-data', d, { contentType: 'application/json', alreadyRedacted: true });
      arts.push(ref.artifact_ref);
      d = { _bounded: true, reason: `data exceeded max_inline_bytes=${this.config.max_inline_bytes}`, artifact_ref: ref.artifact_ref,
        sha256: ref.sha256, original_length: ref.original_length, stored_length: ref.stored_length, truncated: ref.truncated, keys: Object.keys(d).sort().slice(0, 50) };
    }
    const ctx = this.context();
    const merged = Object.fromEntries(ID_FIELDS.map((k) => [k, ids[k] ?? ctx[k] ?? null]));
    return {
      schema_version: SCHEMA_VERSION, event_id: newId('ev'), ts: utcTs(), monotonic_ns: Number(process.hrtime.bigint()), seq: 0,
      level, event_type: eventType, component: component || this.component, host: this.host, pid: this.pid, run_id: this.runId,
      process_id: this.processId, parent_event_id: parentEventId || ctx.parent_event_id || this.parentEventId, ...merged,
      message: msg || null, data: d, log_artifacts: arts.length ? [...new Set(arts)].sort() : null, redaction: rep.asDict(),
    };
  }

  afterRotate(r) {
    if (!r?.closed) return;
    const c = r.closed;
    this.sink.writeEvent(this.build('log.rotate', { closed_segment: c.name, sha256: c.sha256, uncompressed_sha256: c.uncompressed_sha256,
      events: c.events, compressed: c.compressed, index_entry_sha256: c.entry_sha256 }, 'notice', '', 'fwspider-telemetry', null, {}));
    for (const d of r.deleted || []) this.sink.writeEvent(this.build('log.retention_delete', { segment: d.name, sha256: d.sha256, events: d.events, runs: d.runs }, 'notice', '', 'fwspider-telemetry', null, {}));
  }

  failure(err, ev, eventType, critical) {
    this.failures++;
    const info = { error: `${err?.name || 'Error'}: ${this.redactor.text(String(err?.message ?? err))}`, event_type: eventType,
      log_dir: this.config.log_dir, policy: this.config.policy, failures: this.failures, deadletter: this.deadletterPath };
    const rec = { schema_version: 'fwspider.deadletter.v1', ts: utcTs(), reason: info.error, critical, reserved_seq: ev?.seq || null, event: ev };
    let deadOk = true;
    try {
      fs.mkdirSync(this.config.deadletter_dir, { recursive: true, mode: DIR_MODE });
      const fd = fs.openSync(this.deadletterPath, fs.constants.O_WRONLY | fs.constants.O_APPEND | fs.constants.O_CREAT, FILE_MODE);
      try { fs.writeSync(fd, JSON.stringify(rec) + '\n'); } finally { fs.closeSync(fd); }
    } catch (e) { deadOk = false; info.deadletter_error = String(e); }
    if (this.failures <= 3 || this.failures % 100 === 0 || !deadOk) {
      try { process.stderr.write(JSON.stringify({ fwspider_telemetry_failure: info, ...(deadOk ? {} : { event: ev }) }) + '\n'); } catch { /* stderr closed */ }
    }
    if (critical && this.config.policy === 'strict') throw new ObservabilityError(`telemetry unavailable (${info.error}); refusing operation under strict policy`, { cause: err });
  }

  startProcess(argv = process.argv, { kind = 'process', extra = {} } = {}) {
    if (this.started) return null;
    this.started = true;
    let state = {};
    try { this.sink.ensure(); state = this.sink.readState(this.runId); } catch (e) { this.failure(e, null, 'process.start', true); }
    const existing = !!state.seq;
    if (!existing) this.emit('run.start', { run_id: this.runId, log_dir: this.config.log_dir, log_dir_source: this.config.log_dir_source, profile: this.config.profile }, { critical: true });
    const ev = this.emit(existing && !this.parentEventId ? 'process.resume' : 'process.start', {
      kind, argv: this.redactor.argv(argv), cwd: process.cwd(), env: this.redactor.envSummary(process.env, this.config.debug),
      runtime: { node: process.version, platform: process.platform, arch: process.arch }, component_version: this.version,
      config: { ...this.config, extra_redact_patterns: (this.config.extra_redact_patterns || []).length },
      joined_run: this.joinedRun, prior_events_in_run: state.seq || 0, ...extra }, { critical: true });
    this.manifest((m) => {
      m.processes.push({ process_id: this.processId, component: this.component, pid: this.pid, host: this.host, started_at: utcTs(),
        ended_at: null, exit_code: null, status: 'running', argv_sha256: sha256(JSON.stringify(argv.map(String))), parent_event_id: this.parentEventId });
      m.components[this.component] = { version: this.version, git_commit: null };
      m.runtime = { node: process.version, platform: process.platform };
      m.log_dir = this.config.log_dir; m.log_dir_source = this.config.log_dir_source;
    });
    return ev;
  }

  manifest(mutate) { try { this.sink.updateManifest(this.runId, mutate); } catch (e) { this.failure(e, null, 'manifest.update', false); } }

  endProcess(exitCode = 0, { status, data = {} } = {}) {
    if (this.ended) return;
    this.ended = true;
    const st = status || (exitCode === 0 ? 'ok' : 'error');
    this.emit('process.end', { exit_code: exitCode, status: st, duration_ms: Number(process.hrtime.bigint() - this.t0) / 1e6,
      telemetry_failures: this.failures, ...data }, { level: exitCode === 0 ? 'info' : 'warning' });
    this.manifest((m) => {
      for (const p of m.processes) if (p.process_id === this.processId) Object.assign(p, { ended_at: utcTs(), exit_code: exitCode, status: st });
      m.telemetry_failures = (m.telemetry_failures || 0) + this.failures;
    });
  }

  crash(err) {
    if (this.ended) return;
    this.emit('process.crash', { exception: exceptionData(err) });
    this.endProcess(1, { status: 'crashed' });
  }

  installHooks(signals = ['SIGTERM', 'SIGHUP', 'SIGINT']) {
    // uncaughtExceptionMonitor observes without changing Node's default crash behaviour
    process.on('uncaughtExceptionMonitor', (err) => { try { this.crash(err); } catch { /* best effort */ } });
    for (const sig of signals) {
      const handler = () => {
        try { this.emit('process.signal', { signal: sig }); this.endProcess(128 + (os.constants.signals[sig] || 0), { status: 'signalled' }); } catch { /* best effort */ }
        process.removeListener(sig, handler);
        process.kill(process.pid, sig);  // re-deliver with the default disposition
      };
      process.on(sig, handler);
    }
  }

  exception(err, { eventType = 'error.exception', retry = null, level, message = '', data = {}, ids = {} } = {}) {
    const ctx = { ...this.context(), ...ids };
    return this.emit(eventType, { exception: exceptionData(err, retry), retry,
      affected_ids: Object.fromEntries(ID_FIELDS.filter((k) => ctx[k]).map((k) => [k, ctx[k]])), ...data },
    { level, message: message || err?.name || 'Error', ids });
  }

  recordConfig(name, source, value, ids = {}) {
    const d = 'sha256:' + sha256(JSON.stringify(value));
    this.emit('config.load', { name, source, digest: d, effective: value }, { ids });
    this.manifest((m) => { m.config_digests[name] = d; });
    return d;
  }

  recordIo(direction, role, { path: p = null, sha256: h = null, size = null, ref = null } = {}) {
    const item = { role, path: p, sha256: h, size, ref };
    this.manifest((m) => { const key = direction === 'input' ? 'inputs' : 'outputs'; if (!m[key].some((x) => JSON.stringify(x) === JSON.stringify(item))) m[key].push(item); });
  }

  artifact(kind, content, { contentType, alreadyRedacted = false, maxBytes } = {}) {
    maxBytes = maxBytes || this.config.max_artifact_bytes;
    const ref = newId('art');
    const rep = new Report();
    const base = { schema_version: SCHEMA.artifact_envelope.schema_version, artifact_ref: ref, kind, created_at: utcTs(), run_id: this.runId,
      process_id: this.processId, context: this.context() };
    let env;
    const isBinary = Buffer.isBuffer(content) && (content.includes(0) || Buffer.from(content.toString('utf8'), 'utf8').compare(content) !== 0);
    if (isBinary) {
      env = { ...base, content_type: 'application/octet-stream', encoding: null, sha256: sha256(content), original_length: content.length,
        pre_redaction_length: content.length, stored_length: 0, stored_sha256: sha256(''), truncated: content.length > 0, max_bytes: maxBytes,
        redaction: { count: 0 }, body: null,
        binary: { type: sniff(content.subarray(0, 600)), preview_hex: content.subarray(0, RULES.binary_preview_bytes || 64).toString('hex'),
          note: 'raw binary bodies are never stored; preview is bounded hex' } };
    } else {
      let text; let pre;
      if (Buffer.isBuffer(content)) content = content.toString('utf8');
      if (typeof content === 'string') { pre = Buffer.byteLength(content); text = alreadyRedacted ? content : this.redactor.text(content, rep, '$.body'); contentType = contentType || 'text/plain'; }
      else { const obj = alreadyRedacted ? content : this.redactor.value(content, rep, '$.body'); text = JSON.stringify(obj, null, 1); pre = Buffer.byteLength(text); contentType = contentType || 'application/json'; }
      const full = Buffer.from(text, 'utf8');
      let stored = full;
      if (full.length > maxBytes) { stored = Buffer.from(full.subarray(0, maxBytes).toString('utf8').replace(/�$/, ''), 'utf8'); if (stored.length > maxBytes) stored = stored.subarray(0, maxBytes); }
      env = { ...base, content_type: contentType, encoding: 'utf-8', sha256: sha256(full), original_length: full.length, pre_redaction_length: pre,
        stored_length: stored.length, stored_sha256: sha256(stored), truncated: stored.length < full.length, max_bytes: maxBytes,
        redaction: rep.asDict() || { count: 0 }, body: stored.toString('utf8') };
    }
    const summary = { artifact_ref: ref, sha256: env.sha256, original_length: env.original_length, stored_length: env.stored_length,
      truncated: env.truncated, path: `runs/${this.runId}/artifacts/${ref}.json`, redactions: env.redaction.count || 0 };
    try { this.sink.writeArtifact(this.runId, ref, env); } catch (e) { this.failure(e, { artifact: summary }, 'artifact.write', false); summary.write_failed = true; }
    if (this.config.debug) this.emit('artifact.write', { artifact_ref: ref, sha256: summary.sha256, original_length: summary.original_length, stored_length: summary.stored_length, truncated: summary.truncated, kind });
    return summary;
  }

}

let _default = null;
export function getTelemetry(component = 'firmware-spider', opts = {}) {
  if (!_default) _default = new Telemetry(component, opts);
  return _default;
}
