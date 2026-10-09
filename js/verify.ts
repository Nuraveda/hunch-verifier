/**
 * In-browser verifier for Funded Hunch leaderboard records (ON-CHAIN-1a). MIT licence.
 * A port of verifier/hunch_verify.py: must hash byte-for-byte like the engine (shared vectors in verifier/vectors.json).
 * Money is never a JS number here: decimal strings become scaled BigInts.
 */
import { keccak_256 } from "@noble/hashes/sha3";
import { sha256 } from "@noble/hashes/sha2";
import { bytesToHex, concatBytes, hexToBytes, utf8ToBytes } from "@noble/hashes/utils";

export type ProofStep = { h: string; left: boolean };
export type Check = { name: string; ok: boolean; detail: string };
export type Entry = { key: string; n: number; root: string };
export type Batch = { seq: number; root: string; groups: number; leaves: number; manifest: Record<string, unknown>;
  tx_hash: string; block_number: number;
  present: { index: number; records: string[]; proof: ProofStep[] } | null;
  absent: { entries: Entry[] } | null };
export type Bundle = { version: number; chain_id: number; contract: string; account_ref: string; account_id: string;
  first_seq: number; last_seq: number; ended: boolean; from_seq: number; next_from_seq: number | null; batches: Batch[]; board: Batch | null };
export type OnChain = { root: string; leaves: number; manifestHash: string };
type Rec = Record<string, any> & { t: string };

export const BOARD_KEY = "00000000-0000-0000-0000-000000000000";
export const AMOY = 80002; // Polygon Amoy: the only network ON-CHAIN-1a commits to
const TERMINAL = ["passed", "breach", "expired"];

/** RFC 8785 for the JSON the engine emits (strings, safe ints, bools, null, ES6-formatted floats). */
export function jcs(v: unknown): string {
  if (v === null || typeof v !== "object") {
    if (typeof v === "number" && !Number.isFinite(v)) throw new Error("non-finite number");
    return JSON.stringify(v);
  }
  if (Array.isArray(v)) return `[${v.map(jcs).join(",")}]`;
  const o = v as Record<string, unknown>;
  return `{${Object.keys(o).filter((k) => o[k] !== undefined).sort().map((k) => `${JSON.stringify(k)}:${jcs(o[k])}`).join(",")}}`;
}

const strip = (h: string) => (h.startsWith("0x") ? h.slice(2) : h).toLowerCase();
const uuidBytes = (u: string) => hexToBytes(u.replace(/-/g, "").toLowerCase());
export const leafHash = (record: string) => keccak_256(concatBytes(new Uint8Array([0]), utf8ToBytes(record)));
const nodeHash = (l: Uint8Array, r: Uint8Array) => keccak_256(concatBytes(new Uint8Array([1]), l, r));
export function entryHash(key: string, n: number, groupRoot: Uint8Array): Uint8Array {
  const len = new Uint8Array(4);
  new DataView(len.buffer).setUint32(0, n);
  return keccak_256(concatBytes(new Uint8Array([2]), uuidBytes(key), len, groupRoot));
}
export function merkleRoot(nodes: Uint8Array[]): Uint8Array {
  let level = nodes;
  while (level.length > 1) {
    const next: Uint8Array[] = [];
    for (let i = 0; i < level.length; i += 2) next.push(i + 1 < level.length ? nodeHash(level[i], level[i + 1]) : level[i]);
    level = next;
  }
  return level[0];
}
/** Fold a proof; null unless its shape is exactly that of position `index` among `n` nodes. */
export function walk(start: Uint8Array, proof: ProofStep[], index: number, n: number): string | null {
  if (!(index >= 0 && index < n)) return null;
  let h = start, k = 0;
  while (n > 1) {
    const sib = index ^ 1;
    if (sib < n) {
      const s = proof[k++];
      if (!s || s.left !== sib < index) return null;
      h = s.left ? nodeHash(hexToBytes(strip(s.h)), h) : nodeHash(h, hexToBytes(strip(s.h)));
    }
    index = Math.floor(index / 2); n = Math.ceil(n / 2);
  }
  return k === proof.length ? bytesToHex(h) : null;
}
export const manifestHash = (m: Record<string, unknown>) => "0x" + bytesToHex(keccak_256(utf8ToBytes(jcs(m))));
export const accountRef = (accountId: string) => bytesToHex(sha256(utf8ToBytes(accountId))).slice(0, 12);

/** Decimal string -> BigInt scaled by 10^12 (the engine's numerics have far fewer places). */
const S = 12n;
function dec(a: string): bigint {
  const neg = a.startsWith("-");
  const [w, f = ""] = (neg ? a.slice(1) : a).split(".");
  if (f.length > Number(S)) throw new Error("too many decimals");
  const v = BigInt(w + f.padEnd(Number(S), "0"));
  return neg ? -v : v;
}
function show(v: bigint): string {
  const neg = v < 0n, s = (neg ? -v : v).toString().padStart(Number(S) + 1, "0");
  const out = `${s.slice(0, -Number(S))}.${s.slice(-Number(S))}`.replace(/\.?0+$/, "");
  return (neg ? "-" : "") + out;
}
/** (equity / tier − 1) × 100, rounded half-even to 2 places — same as the engine. */
export function pct(equity: string, tier: string): string {
  const e = dec(equity), t = dec(tier);
  const num = (e - t) * 10000n;
  const neg = num < 0n, a = neg ? -num : num;
  let q = a / t;
  const r = a % t;
  if (r * 2n > t || (r * 2n === t && q % 2n === 1n)) q += 1n;
  const s = q.toString().padStart(3, "0");
  return `${neg && q !== 0n ? "-" : ""}${s.slice(0, -2)}.${s.slice(-2)}`;
}

function parse(record: string): Rec | null {
  try {
    const o = JSON.parse(record);
    return o && typeof o === "object" && !Array.isArray(o) && jcs(o) === record ? (o as Rec) : null;
  } catch { return null; }
}

const keyHex = (k: string) => k.replace(/-/g, "").toLowerCase();

/** A batch's FULL entry list: exactly `groups` entries, keys strictly increasing, rebuilding `root` (hex, no 0x). */
export function checkEntries(entries: Entry[], groups: number, root: string): string | null {
  const keys = entries.map((e) => keyHex(e.key));
  if (!entries.length || entries.length !== groups || keys.some((k, i) => i > 0 && !(keys[i - 1] < k)))
    return "entry list is not the whole batch in key order";
  const r = merkleRoot(entries.map((e) => entryHash(e.key, e.n, hexToBytes(strip(e.root)))));
  return bytesToHex(r) === root ? null : "entry list doesn't rebuild the root";
}

/** Spot check of a whole batch (GET /chain/batches/{seq}): on-chain and built by the published rules. */
export function auditBatch(b: Batch & { entries: Entry[] }, chain: OnChain | null | undefined): string | null {
  if (!chain || strip(chain.root) !== strip(b.root) || chain.leaves !== b.leaves || strip(manifestHash(b.manifest)) !== strip(chain.manifestHash))
    return "batch differs from the chain";
  if (b.entries.reduce((t, e) => t + e.n, 0) !== b.leaves) return "entry counts don't add up to the leaf count";
  return checkEntries(b.entries, b.groups, strip(chain.root));
}

export function checkBatch(b: Batch, key: string, chain: OnChain | null | undefined): { problem: string | null; recs: Rec[] } {
  const fail = (problem: string) => ({ problem, recs: [] as Rec[] });
  if (!chain) return fail("no Committed event on-chain");
  const m = b.manifest;
  if (strip(chain.root) !== strip(b.root) || chain.leaves !== b.leaves || strip(manifestHash(m)) !== strip(chain.manifestHash))
    return fail("root, leaf count or manifest differs from the chain");
  if (m.seq !== b.seq || m.root !== b.root || m.groups !== b.groups || m.leaves !== b.leaves) return fail("manifest does not describe this batch");
  if ((b.present === null) === (b.absent === null)) return fail("needs exactly one of present / absent");
  const root = strip(b.root);
  if (b.present) {
    const recs = b.present.records.map(parse);
    if (!recs.length || recs.some((r) => r === null)) return fail("a record is not canonical JSON");
    const e = entryHash(key, recs.length, merkleRoot(b.present.records.map(leafHash)));
    if (walk(e, b.present.proof, b.present.index, b.groups) !== root) return fail("records don't prove into the root (one is missing, extra or changed)");
    return { problem: null, recs: recs as Rec[] };
  }
  const problem = checkEntries(b.absent!.entries ?? [], b.groups, root);
  if (problem) return fail(problem);
  if (b.absent!.entries.some((e) => keyHex(e.key) === keyHex(key))) return fail("the account IS in this batch but its records were withheld");
  return { problem: null, recs: [] };
}

/** `b` = all pages merged. getLog(seq, block) reads the Committed event; chainLastSeq = HunchLedger.lastSeq(). */
export async function verifyAccount(b: Bundle, getLog: (seq: number, block: number) => Promise<OnChain | null>,
  opts: { expectedRef?: string; chainLastSeq?: number;
    /** what the page displays for this trader; it must equal the committed board */
    shown?: { board: string | null; rank: number | null; return_pct: string | null } } = {}): Promise<Check[]> {
  const out: Check[] = [];
  out.push({ name: "Network", ok: b.chain_id === AMOY, detail: b.chain_id === AMOY ? `Polygon Amoy (chain ${AMOY})` : `the record names chain ${b.chain_id}, not Amoy` });
  const ref = accountRef(b.account_id);
  out.push({ name: "This trader's record", ok: ref === b.account_ref && (!opts.expectedRef || opts.expectedRef === ref), detail: `account ${ref}` });
  const seqs = b.batches.map((x) => x.seq);
  const want = Array.from({ length: Math.max(0, b.last_seq - b.first_seq + 1) }, (_, i) => b.first_seq + i);
  let coverOk = seqs.length > 0 && seqs.join() === want.join();
  let coverDetail = coverOk ? `Batches ${b.first_seq}–${b.last_seq}, none missing` : "A batch is missing or out of order";
  if (coverOk && opts.chainLastSeq !== undefined && opts.chainLastSeq - b.last_seq > 1) {
    coverOk = false; coverDetail = `Chain is at batch ${opts.chainLastSeq}, record stops at ${b.last_seq}`;
  }
  out.push({ name: "Nothing left out", ok: coverOk, detail: coverDetail });
  const recsBy = new Map<number, Rec[]>();
  const bad: string[] = [];
  for (const x of b.batches) {
    const c = checkBatch(x, b.account_id, await getLog(x.seq, x.block_number));
    if (c.problem) bad.push(`batch ${x.seq}: ${c.problem}`);
    recsBy.set(x.seq, c.recs);
  }
  out.push({ name: "Matches Polygon", ok: !bad.length, detail: bad.length ? bad.join("; ") : `${seqs.length} batches match the chain` });
  const records = seqs.flatMap((s) => recsBy.get(s) ?? []);
  out.push({ name: "One account", ok: records.every((r) => r.account_id === b.account_id), detail: "every record names this account" });
  const accounts = records.filter((r) => r.t === "account");
  const first = recsBy.get(b.first_seq) ?? [];
  out.push({ name: "Challenge terms", ok: accounts.length === 1 && first.includes(accounts[0]), detail: "committed in the first batch" });
  if (accounts.length !== 1) return out;
  const tier = String(accounts[0].tier);
  const ledger = records.filter((r) => r.t === "ledger_entries");
  const starts = ledger.filter((r) => r.kind === "start_balance").map((r) => String(r.amount));
  out.push({ name: "Starting balance", ok: starts.length === 1 && dec(starts[0]) === dec(tier), detail: `$${tier}` });
  out.push({ name: "Cash from the ledger", ok: true, detail: `$${show(ledger.reduce((t, r) => t + dec(String(r.amount)), 0n))}` });
  const ends = records.filter((r) => r.t === "rule_events" && TERMINAL.includes(r.kind));
  const last = recsBy.get(b.last_seq) ?? [];
  const marks = last.filter((r) => r.t === "mark");
  if (ends.length) {
    const ok = ends.length === 1 && b.ended;
    out.push({ name: "Outcome", ok, detail: ok ? `ended: ${ends[0].kind}` : "ending events don't match the record" });
  } else {
    const ok = !b.ended && marks.length === 1;
    out.push({ name: "Outcome", ok, detail: ok ? "active" : "active account without a mark in the latest batch" });
  }
  let result: string | null = null;
  if (ends.length && ends[0].kind === "passed") result = String(ends[0].evidence.equity);
  else if (!ends.length && marks.length && marks[0].equity !== null) result = String(marks[0].equity);
  if (result !== null) out.push({ name: "Return", ok: true, detail: `${pct(result, tier)}% (equity $${result})` });

  const optins = records.filter((r) => r.t === "optin");
  const opted = optins.length ? optins[optins.length - 1].opted_in === true : false;
  if (!b.board || b.board.seq !== b.last_seq) { out.push({ name: "Leaderboard", ok: false, detail: "the latest board is missing from the record" }); return out; }
  const c = checkBatch(b.board, BOARD_KEY, await getLog(b.board.seq, b.board.block_number));
  if (c.problem || c.recs.length !== 1 || c.recs[0].t !== "board") { out.push({ name: "Leaderboard", ok: false, detail: c.problem ?? "board record missing" }); return out; }
  const rec = c.recs[0];
  const rankBad = boardProblems(rec);
  out.push({ name: "Ranking", ok: !rankBad.length, detail: rankBad.length ? rankBad.join("; ") : `board ${b.board.seq} is ranked by its rules` });
  const where = (["live", "paused", "fame"] as const).flatMap((name) => (rec[name] as Rec[]).map((r, i) => ({ name, i, r }))).filter((x) => x.r.ref === ref);
  let place: string | null;
  if (!opted || (ends.length && ends[0].kind !== "passed")) place = null;
  else if (ends.length) place = "fame";
  else if (!marks.length || marks[0].equity === null || secs(rec.at) - secs(marks[0].marked_at) > STALE_S) place = "paused";
  else place = "live";
  const got = where.length ? where[0].name : null;
  const rank = where.length && got !== "paused" ? where[0].i + 1 : null;
  const row = where.length ? where[0].r : null;
  let ok = true, detail: string;
  if (where.length > 1 || got !== place) { ok = false; detail = `the committed board should list this trader as ${place ?? "absent"}, it shows ${got ?? "absent"}`; }
  else if ((place === "live" || place === "fame") && row!.return_pct !== pct(result!, tier)) { ok = false; detail = "the committed board shows a different return than the trader's own records"; }
  else if ((place === "live" || place === "paused") && marks.length && (row!.equity !== marks[0].equity || row!.marked_at !== marks[0].marked_at)) { ok = false; detail = "the committed board uses a different mark than the trader's own records"; }
  else if (row && (dec(String(row.tier)) !== dec(tier) || row.kind !== accounts[0].kind)) { ok = false; detail = "the committed board shows different challenge terms than the trader's own records"; }
  else if ((place === "live" || place === "paused") && row!.since !== accounts[0].started_at) { ok = false; detail = "the committed board shows a different start than the trader's own records"; }
  else if (place === "fame" && (dec(String(row!.equity)) !== dec(result!) || row!.passed_at !== ends[0].created_at)) { ok = false; detail = "the committed board shows a different pass than the trader's own records"; }
  else detail = got === null ? `not on board ${b.board.seq}` : got === "paused" ? `paused on board ${b.board.seq}` : `#${rank} on the ${got === "fame" ? "hall of fame" : "live board"} (board ${b.board.seq})`;
  if (ok && opts.shown && (opts.shown.board !== got || opts.shown.rank !== rank || opts.shown.return_pct !== (row ? row.return_pct : null))) {
    ok = false; detail = "the page shows a different place or return than the committed board";
  }
  out.push({ name: "Leaderboard", ok, detail });
  return out;
}

const STALE_S = 300; // board rule: a mark older than 5 minutes at the cut is paused
/** "2026-10-06T12:09:00.000000Z" -> seconds since epoch (parsed by hand: no reliance on Date's fraction handling). */
function secs(t: string): number {
  const m = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})\.(\d{6})Z$/.exec(t);
  if (!m) return NaN;
  return Date.UTC(+m[1], +m[2] - 1, +m[3], +m[4], +m[5], +m[6]) / 1000 + +m[7] / 1e6;
}
/** a/b vs c/d for positive tiers, exactly. */
const cmpRet = (a: Rec, z: Rec) => { const l = dec(a.equity) * dec(z.tier), r = dec(z.equity) * dec(a.tier); return l > r ? -1 : l < r ? 1 : 0; };
const cmpStr = (a: string, z: string) => (a < z ? -1 : a > z ? 1 : 0);
const inOrder = (rows: Rec[], cmp: (a: Rec, z: Rec) => number) => rows.every((r, i) => i === 0 || cmp(rows[i - 1], r) <= 0);

/** The board's own rules: unique refs; live by return, then start, then ref; fame by return, then pass time, then
 * ref; paused by ref; every shown return = pct(equity, tier). */
export function boardProblems(rec: Rec): string[] {
  const bad: string[] = [];
  const refs = [...rec.live, ...rec.paused, ...rec.fame].map((r: Rec) => r.ref);
  if (new Set(refs).size !== refs.length) bad.push("a trader appears twice");
  if (!inOrder(rec.live, (a, z) => cmpRet(a, z) || cmpStr(a.since, z.since) || cmpStr(a.ref, z.ref))) bad.push("live board out of order");
  if (!inOrder(rec.fame, (a, z) => cmpRet(a, z) || cmpStr(a.passed_at, z.passed_at) || cmpStr(a.ref, z.ref))) bad.push("hall of fame out of order");
  if (!inOrder(rec.paused, (a, z) => cmpStr(a.ref, z.ref))) bad.push("paused list out of order");
  if ([...rec.live, ...rec.fame].some((r: Rec) => r.return_pct !== pct(r.equity, r.tier))) bad.push("a return doesn't match its equity");
  return bad;
}

/** A published board on its own: committed on-chain, and ranked by its own rules. */
export async function verifyBoard(board: Batch, getLog: (seq: number, block: number) => Promise<OnChain | null>): Promise<Check[]> {
  const c = checkBatch(board, BOARD_KEY, await getLog(board.seq, board.block_number));
  if (c.problem || c.recs.length !== 1 || c.recs[0].t !== "board") return [{ name: "Board on-chain", ok: false, detail: c.problem ?? "board record missing" }];
  const bad = boardProblems(c.recs[0]);
  return [{ name: "Board on-chain", ok: true, detail: `board ${board.seq}` },
    { name: "Ranking", ok: !bad.length, detail: bad.length ? bad.join("; ") : "ranked by its rules" }];
}
