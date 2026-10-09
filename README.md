# Funded Hunch verifier

Check a Funded Hunch leaderboard record yourself, against Polygon, without trusting Funded Hunch.
MIT licence (this directory only). Spec: ON-CHAIN-1a.

```bash
pip install rfc8785 pycryptodome httpx
python hunch_verify.py https://api.fundedhunch.com/leaderboard/<nickname>/<ref>/bundle --ref <ref> --contract <address>
python hunch_verify.py saved-record.json --ref <ref> --contract <address>  # a file from the site's Verify panel
```

It downloads every page of the trader's record, reads each batch's `Committed` event from a public Polygon RPC
(`--rpc`), and checks:

- **This trader's record** — `sha256(account_id)[:12]` is the ref in the link.
- **Nothing left out** — every batch from the one holding the challenge terms to the one holding the ending event
  (or the latest) is there; each shows ALL the account's records in it (they rebuild the account's entry, which
  proves into the on-chain root at its position) or the batch's full sorted entry list without the account.
- **Matches Polygon** — root, leaf count and manifest hash equal the on-chain event; records are canonical JSON.
- **The result** — starting balance = challenge terms; cash = ledger; return from the last hourly mark (live) or the
  pass event (hall of fame); the committed leaderboard shows the same return.
- **The board** — the latest committed board is in the record; the trader is on it exactly where their own records
  say (opted in and active → live or paused with the same mark; passed → hall of fame with the pass equity; otherwise
  absent), and the board is ranked by its own rules.
- **Audit** — whole batches (`/chain/batches/{seq}`): sorted, unique keys rebuilding the root, so no account can have
  a second, hidden group. By default every batch (up to 200; beyond that the newest + 20 at random); `--audit N`.

`--contract` is required: pass the HunchLedger address Funded Hunch publishes.

| | |
|---|---|
| Network | Polygon Amoy testnet (chain id 80002) |
| Contract (`HunchLedger`) | `0x4691389e701B99F780200A1912752d1b2DB8d9FD` |
| Deployed | block 49746691, tx `0x0d83422399d9a8138d51693fcc0592941a46550747a3a0bbeff662292125630a` |
| Owner (can replace the committer) | `0xAB8d7aA79f3292aACaF1bA41a2C82e514E0e0C4f` |
| Committer (appends batches) | `0x3198DeC8F5F2607fD73eF34470CAd881D04d64f9` |

The default `--rpc` is a public Amoy node; pass any other you trust. A record naming any other contract fails, so a
substituted record can't point you at a look-alike contract.

## The tree
```
leaf  = keccak256(0x00 ‖ record text, UTF-8)                      record = RFC 8785 JSON
group = merkle(the account's leaves)        node = keccak256(0x01 ‖ left ‖ right), odd node promoted
entry = keccak256(0x02 ‖ account_id (16 bytes) ‖ n (uint32 BE) ‖ group root)
root  = merkle(entries sorted by key)       the leaderboard uses the all-zero key
manifestHash = keccak256(JCS({v, seq, cut_at, groups, leaves, root}))
```
`vectors.json` holds test vectors generated from Funded Hunch's own engine hashing; the Python and browser verifiers are
both tested against it. (The generator lives in Funded Hunch's private monorepo, which also publishes this repo.)
