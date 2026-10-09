"""Independent verifier for Funded Hunch leaderboard records (MIT licence, see LICENSE).

Checks an account's bundle against the HunchLedger contract on Polygon: every batch from the account's first to its
last is present, each batch either contains ALL of the account's records (its group entry) or provably none of them
(the batch's full, sorted entry list), every root and manifest matches the Committed event on-chain, and the result
follows from the records. Depends only on rfc8785, pycryptodome and httpx — not on Funded Hunch's code or servers
(except to download the bundle, which you can also save and pass as a file).

usage: python hunch_verify.py BUNDLE_URL_OR_FILE [--ref ACCOUNT_REF] [--rpc URL] [--api URL] [--audit N]

BUNDLE can be the URL of the first page (all pages are fetched) or a file saved from the site's Verify panel.
"""
from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import random
import re
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from decimal import ROUND_HALF_EVEN, Decimal
from uuid import UUID

import rfc8785
from Crypto.Hash import keccak

BOARD_KEY = UUID(int=0)
AMOY = 80002  # Polygon Amoy: the only network ON-CHAIN-1a commits to
TERMINAL = ("passed", "breach", "expired")
COMMITTED_TOPIC = "0xbeb80017cbe749ec79b8820688bf7280ddca6f5b23b2e7dbe11ebc91f49712ff"
LAST_SEQ_SELECTOR = "0xec6a43c1"  # lastSeq()


def keccak256(b: bytes) -> bytes:
    return keccak.new(digest_bits=256, data=b).digest()


def _h(s: str) -> bytes:
    return bytes.fromhex(s[2:] if s.startswith("0x") else s)


def leaf(record: str) -> bytes:
    return keccak256(b"\x00" + record.encode())


def node(left: bytes, right: bytes) -> bytes:
    return keccak256(b"\x01" + left + right)


def entry(key: UUID, n: int, group_root: bytes) -> bytes:
    return keccak256(b"\x02" + key.bytes + n.to_bytes(4, "big") + group_root)


def merkle_root(nodes: list[bytes]) -> bytes:
    level = list(nodes)
    while len(level) > 1:
        level = [node(level[i], level[i + 1]) if i + 1 < len(level) else level[i] for i in range(0, len(level), 2)]
    return level[0]


def walk(start: bytes, proof: list[dict], index: int, n: int) -> bytes | None:
    """Fold a proof; None unless its shape is exactly that of position `index` among `n` nodes."""
    if not 0 <= index < n:
        return None
    h, steps = start, list(proof)
    while n > 1:
        sib = index ^ 1
        if sib < n:
            if not steps:
                return None
            s = steps.pop(0)
            if s["left"] != (sib < index):
                return None
            h = node(_h(s["h"]), h) if s["left"] else node(h, _h(s["h"]))
        index, n = index // 2, (n + 1) // 2
    return None if steps else h


def manifest_hash(manifest: dict) -> bytes:
    return keccak256(rfc8785.dumps(manifest))


def account_ref(account_id: str) -> str:
    return hashlib.sha256(account_id.encode()).hexdigest()[:12]


def pct(equity: Decimal, tier: Decimal) -> str:
    q = ((equity / tier - 1) * 100).quantize(Decimal("0.01"), rounding=ROUND_HALF_EVEN)
    return format(q.copy_abs() if q.is_zero() else q, "f")  # never "-0.00"


@dataclass(frozen=True)
class Check:
    name: str
    ok: bool
    detail: str


def _parse(record: str) -> dict | None:
    try:
        obj = json.loads(record)
    except ValueError:
        return None
    try:
        return obj if isinstance(obj, dict) and rfc8785.dumps(obj).decode() == record else None
    except Exception:  # noqa: BLE001 - anything rfc8785 refuses is not canonical
        return None


def check_entries(entries: list[dict], groups: int, root: bytes) -> str | None:
    """A batch's FULL entry list: exactly `groups` entries, keys strictly increasing, rebuilding `root`."""
    keys = [UUID(e["key"]).bytes for e in entries]
    if not entries or len(entries) != groups or keys != sorted(set(keys)):
        return "entry list is not the whole batch in key order"
    if merkle_root([entry(UUID(e["key"]), e["n"], _h(e["root"])) for e in entries]) != root:
        return "entry list doesn't rebuild the root"
    return None


def audit_batch(b: dict, onchain: dict) -> str | None:
    """Spot check of a whole batch (GET /chain/batches/{seq}): on-chain, and built by the published rules — sorted
    unique keys — so no account can have two groups or a hidden one. Returns a problem or None."""
    got = onchain.get(b["seq"])
    if got is None or (got[0], got[1]) != (_h(b["root"]), b["leaves"]) or manifest_hash(b["manifest"]) != got[2]:
        return "batch differs from the chain"
    if sum(e["n"] for e in b["entries"]) != b["leaves"]:
        return "entry counts don't add up to the leaf count"
    return check_entries(b["entries"], b["groups"], got[0])


def check_batch(b: dict, key: UUID, onchain: dict) -> tuple[str | None, list[dict]]:
    """(problem or None, parsed records of `key` in this batch)."""
    got = onchain.get(b["seq"])
    m = b["manifest"]
    if got is None:
        return "no Committed event on-chain", []
    root, leaves, mh = got
    if (root, leaves) != (_h(b["root"]), b["leaves"]) or manifest_hash(m) != mh:
        return "root, leaf count or manifest differs from the chain", []
    if (m.get("seq"), m.get("root"), m.get("groups"), m.get("leaves")) != (b["seq"], b["root"], b["groups"], b["leaves"]):
        return "manifest does not describe this batch", []
    p, a = b.get("present"), b.get("absent")
    if (p is None) == (a is None):
        return "needs exactly one of present / absent", []
    if p is not None:
        recs = [_parse(r) for r in p["records"]]
        if not p["records"] or any(r is None for r in recs):
            return "a record is not canonical JSON", []
        e = entry(key, len(p["records"]), merkle_root([leaf(r) for r in p["records"]]))
        if walk(e, p["proof"], p["index"], b["groups"]) != root:
            return "records don't prove into the root (one is missing, extra or changed)", []
        return None, recs
    problem = check_entries(a.get("entries") or [], b["groups"], root)
    if problem:
        return problem, []
    if key.bytes in [UUID(e["key"]).bytes for e in a["entries"]]:
        return "the account IS in this batch but its records were withheld", []
    return None, []


def verify_account(bundle: dict, onchain: dict[int, tuple[bytes, int, bytes]], *, expected_ref: str | None = None,
                   chain_last_seq: int | None = None, shown: dict | None = None) -> list[Check]:
    """`bundle` = all pages merged (batches concatenated). onchain[seq] = (root, leaves, manifest_hash).
    `shown` = what a page displays for this trader: {"board": "live"|"fame"|"paused"|None, "rank", "return_pct"}."""
    out: list[Check] = []
    out.append(Check("network", bundle.get("chain_id") == AMOY, f"Polygon Amoy (chain {AMOY})"
                     if bundle.get("chain_id") == AMOY else f"the record names chain {bundle.get('chain_id')}, not Amoy"))
    aid = bundle["account_id"]
    ref = account_ref(aid)
    out.append(Check("account", ref == bundle["account_ref"] and (expected_ref in (None, ref)),
                     f"records belong to account {ref}"))
    key = UUID(aid)

    seqs = [b["seq"] for b in bundle["batches"]]
    want = list(range(bundle["first_seq"], bundle["last_seq"] + 1))
    cover_ok = seqs == want and bool(want)
    detail = f"batches {bundle['first_seq']}–{bundle['last_seq']}, none missing"
    if cover_ok and chain_last_seq is not None and chain_last_seq - bundle["last_seq"] > 1:
        cover_ok, detail = False, f"chain is at batch {chain_last_seq}, bundle stops at {bundle['last_seq']}"
    out.append(Check("coverage", cover_ok, detail if seqs == want else "a batch is missing or out of order"))

    recs_by_seq: dict[int, list[dict]] = {}
    bad = []
    for b in bundle["batches"]:
        problem, recs = check_batch(b, key, onchain)
        if problem:
            bad.append(f"batch {b['seq']}: {problem}")
        recs_by_seq[b["seq"]] = recs
    out.append(Check("batches", not bad, "; ".join(bad) if bad else f"{len(seqs)} batches match Polygon"))

    records = [r for s in seqs for r in recs_by_seq.get(s, [])]
    out.append(Check("one_account", all(r.get("account_id") == aid for r in records),
                     "every record names this account"))
    first = recs_by_seq.get(bundle["first_seq"], [])
    accounts = [r for r in records if r["t"] == "account"]
    out.append(Check("start", len(accounts) == 1 and accounts[0] in first, "challenge terms committed in the first batch"))
    if len(accounts) != 1:
        return out
    tier = Decimal(accounts[0]["tier"])

    ledger = [r for r in records if r["t"] == "ledger_entries"]
    starts = [Decimal(r["amount"]) for r in ledger if r["kind"] == "start_balance"]
    out.append(Check("start_balance", starts == [tier], f"starting balance ${format(tier, 'f')}"))
    cash = sum((Decimal(r["amount"]) for r in ledger), Decimal(0))
    out.append(Check("cash", True, f"cash from the ledger ${format(cash, 'f')}"))

    ends = [r for r in records if r["t"] == "rule_events" and r["kind"] in TERMINAL]
    last = recs_by_seq.get(bundle["last_seq"], [])
    marks = [r for r in last if r["t"] == "mark"]
    if ends:
        ok = len(ends) == 1 and bundle["ended"]
        out.append(Check("outcome", ok, f"ended: {ends[0]['kind']}" if ok else "ending events don't match the bundle"))
    else:  # an active account gets a mark in every batch, the latest included
        ok = not bundle["ended"] and len(marks) == 1
        out.append(Check("outcome", ok, "active" if ok else "active account without a mark in the latest batch"))
    result = None
    if ends and ends[0]["kind"] == "passed":
        result = Decimal(ends[0]["evidence"]["equity"])
    elif not ends and marks and marks[0]["equity"] is not None:
        result = Decimal(marks[0]["equity"])
    if result is not None:
        out.append(Check("return", True, f"{pct(result, tier)}% (equity ${format(result, 'f')})"))

    optins = [r for r in records if r["t"] == "optin"]
    opted = optins[-1]["opted_in"] if optins else False
    board = bundle.get("board")
    if board is None or board["seq"] != bundle["last_seq"]:
        out.append(Check("board", False, "the latest board is missing from the bundle"))
        return out
    problem, recs = check_batch(board, BOARD_KEY, onchain)
    if problem or len(recs) != 1 or recs[0]["t"] != "board":
        out.append(Check("board", False, problem or "board record missing"))
        return out
    rec = recs[0]
    bad = board_problems(rec)
    out.append(Check("ranking", not bad, "; ".join(bad) or f"board {board['seq']} is ranked by its rules"))
    where = [(name, i, r) for name in ("live", "paused", "fame") for i, r in enumerate(rec[name]) if r["ref"] == ref]
    if not opted or (ends and ends[0]["kind"] != "passed"):
        want = None
    elif ends:
        want = "fame"
    elif not marks or marks[0]["equity"] is None or _secs(rec["at"]) - _secs(marks[0]["marked_at"]) > STALE_S:
        want = "paused"
    else:
        want = "live"
    got = where[0][0] if where else None
    rank = where[0][1] + 1 if where and got != "paused" else None
    row = where[0][2] if where else None
    if len(where) > 1 or got != want:
        ok, detail = False, f"the committed board should list this trader as {want or 'absent'}, it shows {got or 'absent'}"
    elif want in ("live", "fame") and row["return_pct"] != pct(result, tier):
        ok, detail = False, "the committed board shows a different return than the trader's own records"
    elif want in ("live", "paused") and marks and (row["equity"], row["marked_at"]) != \
            (marks[0]["equity"], marks[0]["marked_at"]):
        ok, detail = False, "the committed board uses a different mark than the trader's own records"
    elif row is not None and (Decimal(row["tier"]) != tier or row["kind"] != accounts[0]["kind"]):
        ok, detail = False, "the committed board shows different challenge terms than the trader's own records"
    elif want in ("live", "paused") and row["since"] != accounts[0]["started_at"]:
        ok, detail = False, "the committed board shows a different start than the trader's own records"
    elif want == "fame" and (Decimal(row["equity"]) != result or row["passed_at"] != ends[0]["created_at"]):
        ok, detail = False, "the committed board shows a different pass than the trader's own records"
    else:
        ok = True
        detail = {None: f"not on board {board['seq']}", "paused": f"paused on board {board['seq']}"}.get(
            got, f"#{rank} on the {'hall of fame' if got == 'fame' else 'live board'} (board {board['seq']})")
    if ok and shown is not None and shown != {"board": got, "rank": rank,
                                              "return_pct": row["return_pct"] if row else None}:
        ok, detail = False, "the page shows a different place or return than the committed board"
    out.append(Check("board", ok, detail))
    return out


STALE_S = 300  # board rule: a mark older than 5 minutes at the cut is paused


def _secs(t: str) -> float:
    return datetime.strptime(t, "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=timezone.utc).timestamp()


def _ret(r: dict) -> Decimal:
    return Decimal(r["equity"]) / Decimal(r["tier"])


def board_problems(rec: dict) -> list[str]:
    """The board's own rules: unique refs; live by return, then start, then ref; fame by return, then pass time,
    then ref; paused by ref; every shown return = pct(equity, tier)."""
    bad = []
    refs = [r["ref"] for name in ("live", "paused", "fame") for r in rec[name]]
    if len(refs) != len(set(refs)):
        bad.append("a trader appears twice")
    if [r["ref"] for r in rec["live"]] != [r["ref"] for r in sorted(rec["live"], key=lambda r: (-_ret(r), r["since"], r["ref"]))]:
        bad.append("live board out of order")
    if [r["ref"] for r in rec["fame"]] != [r["ref"] for r in sorted(rec["fame"], key=lambda r: (-_ret(r), r["passed_at"], r["ref"]))]:
        bad.append("hall of fame out of order")
    if [r["ref"] for r in rec["paused"]] != sorted(r["ref"] for r in rec["paused"]):
        bad.append("paused list out of order")
    if any(r["return_pct"] != pct(Decimal(r["equity"]), Decimal(r["tier"])) for r in rec["live"] + rec["fame"]):
        bad.append("a return doesn't match its equity")
    return bad


def verify_board(board: dict, onchain: dict[int, tuple[bytes, int, bytes]]) -> list[Check]:
    """A published board on its own: committed, and ranked by its own rules."""
    problem, recs = check_batch(board, BOARD_KEY, onchain)
    if problem or len(recs) != 1 or recs[0]["t"] != "board":
        return [Check("board", False, problem or "board record missing")]
    bad = board_problems(recs[0])
    return [Check("board", True, f"board {board['seq']} is on-chain"),
            Check("ranking", not bad, "; ".join(bad) or "ranked by its rules")]


async def _rpc(http, url: str, method: str, params: list):
    r = await http.post(url, json={"jsonrpc": "2.0", "id": 1, "method": method, "params": params}, timeout=30)
    body = r.json()
    if "error" in body:
        raise RuntimeError(f"{method}: {body['error'].get('message')}")
    return body["result"]


async def fetch_onchain(http, rpc: str, contract: str, batches: list[dict]) -> dict:
    out = {}
    for b in batches:
        logs = await _rpc(http, rpc, "eth_getLogs", [{"address": contract, "fromBlock": hex(b["block_number"]),
                                                      "toBlock": hex(b["block_number"]),
                                                      "topics": [COMMITTED_TOPIC, "0x" + b["seq"].to_bytes(32, "big").hex()]}])
        if logs:
            d = _h(logs[0]["data"])
            out[int(logs[0]["topics"][1], 16)] = (d[0:32], int.from_bytes(d[32:64], "big"), d[64:96])
    return out


async def main() -> int:
    import httpx

    ap = argparse.ArgumentParser()
    ap.add_argument("bundle")
    ap.add_argument("--ref")
    ap.add_argument("--contract", required=True, help="Funded Hunch's published HunchLedger address (0x + 40 hex)")
    ap.add_argument("--rpc", default="https://polygon-amoy-bor-rpc.publicnode.com")
    ap.add_argument("--api", default="https://api.fundedhunch.com", help="where /chain/batches/{seq} is served")
    ap.add_argument("--audit", type=int, default=None,
                    help="whole batches to check (newest + random); default: all up to 200, else 21; -1 = all")
    a = ap.parse_args()
    if not re.fullmatch(r"0x[0-9a-fA-F]{40}", a.contract):
        print("❌ contract — --contract must be an address (0x + 40 hex digits)")
        return 1
    async with httpx.AsyncClient() as http:
        if a.bundle.startswith("http"):
            # each page must start at the cursor asked for and move toward the FIRST page's last_seq: paging always ends
            pages, url, cursor = [], a.bundle, None
            while True:
                r = await http.get(url, timeout=60)
                r.raise_for_status()
                page = r.json()
                if not isinstance(page.get("batches"), list) or not isinstance(page.get("from_seq"), int) \
                        or not isinstance(page.get("last_seq"), int):
                    raise ValueError("not a record page")
                if (cursor is not None and page["from_seq"] != cursor) or \
                        (pages and page["last_seq"] != pages[0]["last_seq"]):
                    raise ValueError("record pages don't line up")
                pages.append(page)
                nxt = page.get("next_from_seq")
                if nxt is None:
                    break
                if not isinstance(nxt, int) or not page["from_seq"] < nxt <= page["last_seq"]:
                    raise ValueError("record pages don't advance")
                cursor = nxt
                url = f"{a.bundle.split('?')[0]}?from_seq={cursor}&to_seq={pages[0]['last_seq']}"  # pinned end
            bundle = {**pages[-1], "batches": [b for p in pages for b in p["batches"]]}
        else:
            bundle = json.load(open(a.bundle))
        if bundle["contract"].lower() != a.contract.lower():
            print(f"❌ contract — the record names {bundle['contract']}, not the published {a.contract}")
            return 1
        batches = bundle["batches"] + ([bundle["board"]] if bundle.get("board") else [])
        onchain = await fetch_onchain(http, a.rpc, bundle["contract"], batches)
        rpc_chain = int(await _rpc(http, a.rpc, "eth_chainId", []), 16)
        if rpc_chain != AMOY:
            print(f"❌ network — the RPC is chain {rpc_chain}, not Polygon Amoy ({AMOY})")
            return 1
        last = int(await _rpc(http, a.rpc, "eth_call", [{"to": bundle["contract"], "data": LAST_SEQ_SELECTOR}, "latest"]), 16)
        checks = verify_account(bundle, onchain, expected_ref=a.ref, chain_last_seq=last)
        seqs = [b["seq"] for b in bundle["batches"]]
        n = a.audit if a.audit is not None else (-1 if len(seqs) <= 200 else 21)
        pick = seqs if n < 0 or n >= len(seqs) else seqs[-1:] + random.sample(seqs[:-1], max(n - 1, 0))
        bad = []
        for seq in pick:
            whole = (await http.get(f"{a.api}/chain/batches/{seq}", timeout=60)).json()
            problem = audit_batch(whole, onchain) if whole.get("seq") == seq else "not served"
            if problem:
                bad.append(f"batch {seq}: {problem}")
        checks.append(Check("audit", not bad, "; ".join(bad) or f"{len(pick)} of {len(seqs)} whole batch(es) built by the rules"))
    for c in checks:
        print("✅" if c.ok else "❌", c.name, "—", c.detail)
    return 0 if all(c.ok for c in checks) else 1


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
