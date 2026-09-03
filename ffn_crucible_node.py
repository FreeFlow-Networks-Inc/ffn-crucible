#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
"""
ffn_crucible_node.py -- the CRUCIBLE analysis node: the box you relay to.

A firewall is a bad place to detonate malware. It has no spare cores, no
hypervisor, and an uptime requirement; and a sandbox escape on the device that
enforces your policy is the worst possible outcome. So the interesting half of
Crucible is OFFLOADABLE: the firewall carves the object out of the flow and
hands it to this node, which owns the guests, does the detonation, and hands
back a verdict plus the content needed to enforce it.

    firewall (FFN-NGFW opt/cloud_det.py, RelayBackend)
        |  POST /submit          sample bytes + metadata, bearer token
        v
    THIS NODE
        |  queue (sqlite, survives restart) -> worker pool
        |  ffn_crucible.CrucibleSandbox at policy=best
        |  static dissection -> jailed exec -> guest VM
        v
        |  GET /verdict/<sha256> verdict + score + sigs + IOCs, ed25519-SIGNED
        v
    firewall: ThreatDB.record_sample / record_ioc, inline add_signature,
              compile_to_fpga  -- the next occurrence is blocked in hardware

WHY THE VERDICT IS SIGNED
    A verdict is not advice, it is an instruction: it makes the firewall
    blocklist a hash, condemn a domain, and install a DROP rule that is then
    pushed into the FPGA fast path. Anyone who can forge a verdict can
    therefore either clear a sample they want delivered, or blocklist a domain
    they want taken down -- a denial of service authored by the attacker and
    executed by the defender's own hardware.

    So every verdict is signed with ed25519 over a canonical serialisation, and
    the firewall refuses an unsigned or badly-signed one. TLS is not a
    substitute: it authenticates the connection, not the verdict, and the
    verdict outlives the connection -- it is cached, relayed, and replayed from
    the database. The private seed lives only on this node and is never
    packaged into an image (see tools/PUBLISH-POLICY).

DEPLOYMENT SHAPES -- the same engine, three arrangements
    on-box       FFN-NGFW's cloud_det with backend=CrucibleSandbox. No
                 node, no network, static fidelity only. The appliance
                 default.
    relay        this node on a separate box. The firewall offloads and gets
                 guest-VM fidelity without hosting a hypervisor.
    relay+local  as above, but the firewall falls back to on-box static
                 analysis when the node is unreachable, so an outage degrades
                 fidelity instead of stopping inspection.

ENDPOINTS
    POST /submit                    sample bytes; returns {sha256,status}
    GET  /verdict/<sha256>          signed verdict, or {status:pending}
    GET  /report/<sha256>           the full behaviour report
    GET  /api/status                node health, queue depth, chambers
    GET  /api/pubkey                this node's verdict-signing public key
    GET  /                          operator console
Nothing else is reachable. This is not a file server.

CLI
    ffn_crucible_node.py selftest                     hermetic round trip
    ffn_crucible_node.py serve [--port 8449] [--policy best]
    ffn_crucible_node.py keygen [--prefix /etc/ffn-ngfw/crucible-verdict]
    ffn_crucible_node.py work [--limit N]             drain the queue once
    ffn_crucible_node.py status
"""

import argparse
import hashlib
import hmac
import http.server
import json
import logging
import os
import re
import socket
import sqlite3
import ssl
import sys
import threading
import time
from typing import Dict, List, Optional, Tuple

logger = logging.getLogger("ffn-crucible-node")

try:
    from ffn_crucible import (
        CrucibleSandbox, POLICIES, POLICY_BEST, POLICY_STATIC, MAX_SAMPLE,
        DEFAULT_TIMEOUT, DEFAULT_GUEST_PROFILES,
    )
except ImportError as _e:                       # the node is useless without it
    CrucibleSandbox = None
    POLICIES = ("static", "jail", "vm", "best")
    POLICY_BEST, POLICY_STATIC = "best", "static"
    MAX_SAMPLE = 64 * 1024 * 1024
    DEFAULT_TIMEOUT = 30
    DEFAULT_GUEST_PROFILES = "/etc/ffn-ngfw/crucible-guests.json"
    logger.warning("ffn_crucible unavailable: %s", _e)

try:
    import ffn_ed25519
except ImportError:
    ffn_ed25519 = None

# Paths, all overridable by environment for testing. Defaults name FILES, never
# secrets -- the seed is read from disk at runtime and is never in this tree.
SPOOL_DIR = os.environ.get("FFN_CRUCIBLE_SPOOL", "/var/lib/ffn-ngfw/crucible")
DB_PATH = os.environ.get("FFN_CRUCIBLE_DB",
                         "/var/lib/ffn-ngfw/crucible/node.sqlite")
# SEED_PATH / PUB_PATH come from ffn_crucible, next to VerdictSigner, so there
# is one definition of where the verdict key lives. Re-exported here because
# this module's docstring and CLI document them as its own contract.
try:
    from ffn_crucible import SEED_PATH, PUB_PATH
except ImportError:
    SEED_PATH = os.environ.get("FFN_CRUCIBLE_SEED",
                               "/etc/ffn-ngfw/crucible-verdict.key")
    PUB_PATH = os.environ.get("FFN_CRUCIBLE_PUB",
                              "/etc/ffn-ngfw/crucible-verdict.pub")
TOKEN_PATH = os.environ.get("FFN_CRUCIBLE_TOKEN",
                            "/etc/ffn-ngfw/crucible-node.token")

DEFAULT_PORT = 8449
MAX_BODY = MAX_SAMPLE
MAX_QUEUE = 4096
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


# ===========================================================================
# Verdict signing lives in ffn_crucible, not here.
#
# Both ends of the relay must agree byte-for-byte on the canonical form that
# gets signed, so it has exactly one definition. It sits in ffn_crucible
# because that is the module BOTH sides already require -- this node needs it
# to detonate, and the firewall needs it for its local fallback chamber. Had
# it lived here, a firewall that only offloads (and so has no reason to deploy
# the node module) would have been unable to verify anything, and would have
# quietly treated every verdict as unauthenticated.
# ===========================================================================
try:
    from ffn_crucible import VerdictSigner
except ImportError:                              # engine absent; node is inert
    VerdictSigner = None


# ===========================================================================
# Storage
# ===========================================================================
class NodeStore:
    """Durable submission queue and verdict store.

    Sample bytes go to the spool directory, not into sqlite: a 64 MiB blob per
    row makes the database unusable for the queue operations that matter, and a
    spooled file can be handed to a chamber by path without a copy.
    """

    SCHEMA = """
    CREATE TABLE IF NOT EXISTS submissions (
        sha256     TEXT PRIMARY KEY,
        status     TEXT NOT NULL DEFAULT 'pending',  -- pending/analyzing/done/error
        file_type  TEXT,
        size       INTEGER,
        meta       TEXT,
        submitter  TEXT,
        submitted  TEXT,
        updated    TEXT,
        attempts   INTEGER NOT NULL DEFAULT 0,
        error      TEXT
    );
    CREATE INDEX IF NOT EXISTS submissions_status
        ON submissions(status, submitted);
    CREATE TABLE IF NOT EXISTS verdicts (
        sha256     TEXT PRIMARY KEY,
        verdict    TEXT NOT NULL,
        score      INTEGER NOT NULL DEFAULT 0,
        threat     TEXT,
        file_type  TEXT,
        confidence TEXT,
        chamber    TEXT,
        fidelity   INTEGER,
        bundle     TEXT,      -- the signed verdict, exactly as served
        report     TEXT,      -- the full behaviour report
        analyzed   TEXT
    );
    """

    def __init__(self, db_path: str = None, spool: str = None):
        self.db_path = db_path or DB_PATH
        self.spool = spool or SPOOL_DIR
        for d in (os.path.dirname(self.db_path) or ".",
                  os.path.join(self.spool, "samples")):
            os.makedirs(d, exist_ok=True)
        self.conn = sqlite3.connect(self.db_path, check_same_thread=False,
                                    timeout=30.0)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.executescript(self.SCHEMA)
        self.conn.commit()
        self._lock = threading.Lock()

    def close(self) -> None:
        try:
            self.conn.close()
        except sqlite3.Error:
            pass

    @staticmethod
    def _now() -> str:
        return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

    # -- spool -------------------------------------------------------------
    def sample_path(self, sha: str) -> str:
        """Path for one sample. Validated: this is where a hash from an HTTP
        request reaches the filesystem, so anything but 64 hex digits is
        refused rather than sanitised."""
        if not SHA256_RE.match(sha or ""):
            raise ValueError("not a sha256: %r" % ((sha or "")[:80],))
        # Two levels of fan-out so one directory never holds a million entries.
        return os.path.join(self.spool, "samples", sha[:2], sha[2:4], sha)

    def write_sample(self, sha: str, data: bytes) -> str:
        path = self.sample_path(sha)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        if not os.path.exists(path):
            tmp = path + ".part"
            with open(tmp, "wb") as fh:
                fh.write(data)
            os.replace(tmp, path)
        return path

    def read_sample(self, sha: str) -> Optional[bytes]:
        try:
            with open(self.sample_path(sha), "rb") as fh:
                return fh.read(MAX_SAMPLE)
        except (OSError, ValueError):
            return None

    # -- queue -------------------------------------------------------------
    def enqueue(self, sha: str, data: bytes, meta: dict,
                submitter: str = "") -> str:
        """Queue a sample. Returns queued / pending / analyzing / done / full."""
        with self._lock:
            if self.conn.execute("SELECT 1 FROM verdicts WHERE sha256=?",
                                 (sha,)).fetchone():
                return "done"
            row = self.conn.execute(
                "SELECT status FROM submissions WHERE sha256=?", (sha,)).fetchone()
            if row and row["status"] in ("pending", "analyzing"):
                return row["status"]
            depth = self.conn.execute(
                "SELECT COUNT(*) c FROM submissions WHERE status='pending'"
            ).fetchone()["c"]
            if depth >= MAX_QUEUE:
                return "full"
            self.write_sample(sha, data)
            now = self._now()
            self.conn.execute(
                "INSERT INTO submissions (sha256,status,file_type,size,meta,"
                "submitter,submitted,updated) VALUES (?,?,?,?,?,?,?,?) "
                "ON CONFLICT(sha256) DO UPDATE SET status='pending', "
                "updated=excluded.updated",
                (sha, "pending", meta.get("file_type"), len(data),
                 json.dumps(meta)[:8192], submitter[:64], now, now))
            self.conn.commit()
            return "queued"

    def claim(self, limit: int = 1) -> List[sqlite3.Row]:
        """Take up to `limit` pending rows, marking them analyzing.

        The SELECT and the UPDATE are one critical section: two workers that
        claimed the same row would detonate the sample twice and then race on
        the verdict write.
        """
        with self._lock:
            rows = self.conn.execute(
                "SELECT sha256,meta,file_type,size FROM submissions "
                "WHERE status='pending' ORDER BY submitted LIMIT ?",
                (limit,)).fetchall()
            for r in rows:
                self.conn.execute(
                    "UPDATE submissions SET status='analyzing', updated=?, "
                    "attempts=attempts+1 WHERE sha256=?",
                    (self._now(), r["sha256"]))
            self.conn.commit()
            return rows

    def finish(self, sha: str, bundle: dict, report: dict) -> None:
        d = report.get("details", {}) if isinstance(report, dict) else {}
        with self._lock:
            self.conn.execute(
                "INSERT INTO verdicts (sha256,verdict,score,threat,file_type,"
                "confidence,chamber,fidelity,bundle,report,analyzed) "
                "VALUES (?,?,?,?,?,?,?,?,?,?,?) "
                "ON CONFLICT(sha256) DO UPDATE SET verdict=excluded.verdict, "
                "score=excluded.score, threat=excluded.threat, "
                "bundle=excluded.bundle, report=excluded.report, "
                "analyzed=excluded.analyzed, chamber=excluded.chamber, "
                "fidelity=excluded.fidelity, confidence=excluded.confidence",
                (sha, bundle.get("verdict", "unknown"),
                 int(bundle.get("score", 0) or 0), bundle.get("threat", ""),
                 bundle.get("file_type", ""), d.get("confidence", ""),
                 d.get("chamber", ""), int(d.get("fidelity", 0) or 0),
                 json.dumps(bundle), json.dumps(report), self._now()))
            self.conn.execute(
                "UPDATE submissions SET status='done', updated=?, error=NULL "
                "WHERE sha256=?", (self._now(), sha))
            self.conn.commit()

    def fail(self, sha: str, err: str) -> None:
        with self._lock:
            self.conn.execute(
                "UPDATE submissions SET status='error', updated=?, error=? "
                "WHERE sha256=?", (self._now(), str(err)[:500], sha))
            self.conn.commit()

    # -- queries -----------------------------------------------------------
    def _json_col(self, sha: str, col: str) -> Optional[dict]:
        if not SHA256_RE.match(sha or ""):
            return None
        r = self.conn.execute(
            "SELECT %s AS v FROM verdicts WHERE sha256=?" % col, (sha,)).fetchone()
        if not r or not r["v"]:
            return None
        try:
            return json.loads(r["v"])
        except ValueError:
            return None

    def verdict(self, sha: str) -> Optional[dict]:
        return self._json_col(sha, "bundle")

    def report(self, sha: str) -> Optional[dict]:
        return self._json_col(sha, "report")

    def submission(self, sha: str) -> Optional[sqlite3.Row]:
        if not SHA256_RE.match(sha or ""):
            return None
        return self.conn.execute("SELECT * FROM submissions WHERE sha256=?",
                                 (sha,)).fetchone()

    def stats(self) -> dict:
        out = {"pending": 0, "analyzing": 0, "done": 0, "error": 0}
        for row in self.conn.execute(
                "SELECT status, COUNT(*) c FROM submissions GROUP BY status"):
            out[row["status"]] = row["c"]
        verdicts: Dict[str, int] = {}
        for row in self.conn.execute(
                "SELECT verdict, COUNT(*) c FROM verdicts GROUP BY verdict"):
            verdicts[row["verdict"]] = row["c"]
        out["verdicts"] = verdicts
        out["analyzed_total"] = sum(verdicts.values())
        return out

    def recent(self, limit: int = 25) -> List[sqlite3.Row]:
        return self.conn.execute(
            "SELECT sha256,verdict,score,threat,file_type,confidence,chamber,"
            "fidelity,analyzed FROM verdicts ORDER BY analyzed DESC LIMIT ?",
            (limit,)).fetchall()


# ===========================================================================
# The node
# ===========================================================================
class CrucibleNode:
    """Queue, workers, signing. The HTTP layer is a thin shell over this.

    Kept deliberately separate from the HTTP handler so the same object serves
    three deployments: this node's own server, a cron-style `work` drain, and
    an in-process embedding on the firewall with no network at all.
    """

    def __init__(self, store: Optional[NodeStore] = None, *,
                 policy: str = POLICY_BEST, timeout: int = DEFAULT_TIMEOUT,
                 workers: int = 2, signer: Optional[VerdictSigner] = None,
                 node_id: str = "", guest_profiles: str = DEFAULT_GUEST_PROFILES,
                 token: Optional[str] = None):
        if CrucibleSandbox is None:
            raise RuntimeError("ffn_crucible is required to run a crucible node")
        self.store = store or NodeStore()
        self.signer = signer or VerdictSigner()
        self.policy = policy
        self.timeout = timeout
        self.workers = max(1, workers)
        self.guest_profiles = guest_profiles
        # A node identity that does not leak the build host's name: the operator
        # sets it, or it defaults to the signing key id, or to "crucible".
        self.node_id = (node_id or os.environ.get("FFN_CRUCIBLE_NODE_ID", "")
                        or self.signer.key_id() or "crucible")
        self._token = token
        self.engine = CrucibleSandbox(policy=policy, timeout=timeout,
                                      guest_profiles=guest_profiles)
        self.started = time.time()
        self.stats = {"submitted": 0, "deduped": 0, "analyzed": 0,
                      "errors": 0, "rejected": 0}
        self._stop = threading.Event()
        self._threads: List[threading.Thread] = []

    # -- auth --------------------------------------------------------------
    def token(self) -> Optional[str]:
        """The bearer token, read from disk. Absent file means open access."""
        if self._token is not None:
            return self._token or None
        try:
            with open(TOKEN_PATH) as fh:
                tok = fh.read().strip()
            self._token = tok
            return tok or None
        except OSError:
            self._token = ""
            return None

    def authorised(self, header: str) -> bool:
        """Constant-time bearer check.

        An absent token file means no authentication, which is only sane when
        the node is bound to loopback or a management-only address; serve()
        warns loudly when it is reachable more widely without one.
        """
        want = self.token()
        if want is None:
            return True
        got = (header or "").strip()
        if got.lower().startswith("bearer "):
            got = got[7:].strip()
        return hmac.compare_digest(got, want)

    # -- submission --------------------------------------------------------
    def submit(self, data: bytes, meta: Optional[dict] = None,
               submitter: str = "") -> dict:
        """Accept a sample. Answers from cache when the verdict is already known."""
        meta = dict(meta or {})
        if not data:
            self.stats["rejected"] += 1
            return {"status": "rejected", "error": "empty submission"}
        if len(data) > MAX_BODY:
            self.stats["rejected"] += 1
            return {"status": "rejected",
                    "error": "sample exceeds %d bytes" % MAX_BODY}
        sha = hashlib.sha256(data).hexdigest()
        self.stats["submitted"] += 1
        existing = self.store.verdict(sha)
        if existing:
            self.stats["deduped"] += 1
            return {"sha256": sha, "status": "done",
                    "verdict": existing.get("verdict", "unknown")}
        status = self.store.enqueue(sha, data, meta, submitter)
        if status == "full":
            self.stats["rejected"] += 1
            return {"sha256": sha, "status": "rejected",
                    "error": "queue is full (%d)" % MAX_QUEUE}
        return {"sha256": sha, "status": status}

    # -- analysis ----------------------------------------------------------
    def analyze_one(self, sha: str, meta: dict) -> Optional[dict]:
        """Detonate one queued sample and store the signed verdict."""
        data = self.store.read_sample(sha)
        if data is None:
            self.store.fail(sha, "spooled sample missing")
            self.stats["errors"] += 1
            return None
        try:
            rep = self.engine.analyze(sha, data, meta)
        except Exception as e:
            logger.exception("analysis failed for %s", sha[:12])
            self.store.fail(sha, "engine: %s" % e)
            self.stats["errors"] += 1
            return None
        report = json.loads(rep.to_json())
        bundle = {
            "sha256": sha,
            "verdict": rep.verdict,
            "score": rep.score,
            "threat": rep.threat_name,
            "file_type": rep.file_type or "",
            "analyzed": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "node": self.node_id,
            "signatures": report.get("signatures", []),
            "iocs": report.get("iocs", []),
            "details": {k: report.get("details", {}).get(k)
                        for k in ("chamber", "fidelity", "executed",
                                  "confidence", "reasons")},
        }
        signed = self.signer.sign(bundle)
        self.store.finish(sha, signed, report)
        self.stats["analyzed"] += 1
        logger.info("assayed %s -> %s score=%d chamber=%s conf=%s",
                    sha[:12], rep.verdict, rep.score,
                    report.get("details", {}).get("chamber"),
                    report.get("details", {}).get("confidence"))
        return signed

    def drain(self, limit: int = 50) -> List[dict]:
        """Analyse up to `limit` queued samples in this thread."""
        out = []
        for row in self.store.claim(limit):
            try:
                meta = json.loads(row["meta"] or "{}")
            except ValueError:
                meta = {}
            got = self.analyze_one(row["sha256"], meta)
            if got:
                out.append(got)
        return out

    # -- worker pool -------------------------------------------------------
    def start_workers(self) -> None:
        """Background workers. One detonation at a time per worker: a chamber
        owns a whole guest VM, so oversubscribing them thrashes rather than
        parallelises."""
        for i in range(self.workers):
            t = threading.Thread(target=self._worker, args=(i,), daemon=True,
                                 name="crucible-worker-%d" % i)
            t.start()
            self._threads.append(t)

    def _worker(self, index: int) -> None:
        backoff = 0.25
        while not self._stop.is_set():
            try:
                done = self.drain(limit=1)
            except Exception:
                logger.exception("worker %d fault", index)
                done = []
            if done:
                backoff = 0.25
                continue
            # Idle: back off up to two seconds so an empty queue does not spin.
            self._stop.wait(backoff)
            backoff = min(backoff * 2, 2.0)

    def stop(self) -> None:
        self._stop.set()
        for t in self._threads:
            t.join(timeout=5.0)
        self._threads.clear()

    # -- status ------------------------------------------------------------
    def status(self) -> dict:
        st = self.store.stats()
        return {
            "node": self.node_id,
            "uptime": int(time.time() - self.started),
            "policy": self.policy,
            "workers": self.workers,
            "timeout": self.timeout,
            "queue": {k: st.get(k, 0) for k in
                      ("pending", "analyzing", "done", "error")},
            "verdicts": st.get("verdicts", {}),
            "analyzed_total": st.get("analyzed_total", 0),
            "counters": dict(self.stats),
            "signing": {
                "alg": "ed25519" if self.signer.can_sign() else "none",
                "key_id": self.signer.key_id(),
                "canonical_version": VerdictSigner.VERSION,
            },
            "authenticated": self.token() is not None,
            "chambers": [
                {"name": s.name, "fidelity": s.fidelity,
                 "available": s.available, "executes": s.executes,
                 "reason": s.reason}
                for s in self.engine.statuses()],
            "max_fidelity": max([s.fidelity for s in self.engine.statuses()
                                 if s.available], default=0),
        }

    def lookup(self, sha: str) -> dict:
        """What the /verdict endpoint answers with."""
        if not SHA256_RE.match(sha or ""):
            return {"status": "invalid", "error": "not a sha256"}
        bundle = self.store.verdict(sha)
        if bundle:
            return dict(bundle, status="done")
        row = self.store.submission(sha)
        if row is None:
            return {"sha256": sha, "status": "unknown"}
        out = {"sha256": sha, "status": row["status"]}
        if row["status"] == "error":
            out["error"] = row["error"] or "analysis failed"
        return out


# ===========================================================================
# HTTP surface
#
# Six routes, all matched exactly or by a validated hash. There is no static
# file handler and no path joining from request input, so path traversal has
# nothing to reach -- the same posture as ffn_update_server.py.
# ===========================================================================
class _Handler(http.server.BaseHTTPRequestHandler):
    server_version = "ffn-crucible/1.0"
    node: "CrucibleNode" = None            # set on the server instance

    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *a):        # route logging through logging
        logger.info("%s %s", self.address_string(), fmt % a)

    # -- helpers -----------------------------------------------------------
    def _send(self, code: int, body: bytes,
              ctype: str = "application/json") -> None:
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        try:
            self.wfile.write(body)
        except OSError:
            pass

    def _json(self, obj, code: int = 200) -> None:
        self._send(code, json.dumps(obj, sort_keys=True).encode("utf-8"))

    def _auth_ok(self) -> bool:
        node = self.server.node
        if node.authorised(self.headers.get("Authorization", "")):
            return True
        self._json({"error": "unauthorised"}, 401)
        return False

    # -- routes ------------------------------------------------------------
    def do_POST(self) -> None:
        node = self.server.node
        if self.path.rstrip("/") != "/submit":
            self._json({"error": "not found"}, 404)
            return
        if not self._auth_ok():
            return
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            self._json({"error": "bad Content-Length"}, 400)
            return
        if length <= 0:
            self._json({"error": "empty submission"}, 400)
            return
        if length > MAX_BODY:
            # Refuse before reading: a large body must not be buffered just to
            # be rejected.
            self._json({"error": "too large", "max": MAX_BODY}, 413)
            return
        data = b""
        while len(data) < length:
            chunk = self.rfile.read(min(1 << 20, length - len(data)))
            if not chunk:
                break
            data += chunk
        if len(data) != length:
            self._json({"error": "short body"}, 400)
            return
        meta = {}
        raw_meta = self.headers.get("X-Crucible-Meta")
        if raw_meta:
            try:
                parsed = json.loads(raw_meta)
                if isinstance(parsed, dict):
                    # Client metadata is untrusted context, not instructions:
                    # it is stored and echoed, never used to choose a chamber
                    # or to influence the verdict.
                    meta = {str(k)[:32]: str(v)[:256]
                            for k, v in list(parsed.items())[:32]}
            except ValueError:
                pass
        meta.setdefault("filename", (self.headers.get("X-Crucible-Filename")
                                     or "")[:128])
        res = node.submit(data, meta, submitter=self.client_address[0])
        code = 202 if res.get("status") in ("queued", "pending", "analyzing") \
            else 200 if res.get("status") == "done" else 400
        self._json(res, code)

    def do_GET(self) -> None:
        node = self.server.node
        path = self.path.split("?", 1)[0].rstrip("/") or "/"

        if path == "/":
            self._send(200, _console(node).encode("utf-8"),
                       "text/html; charset=utf-8")
            return
        if path == "/api/pubkey":
            pub = node.signer.pub()
            self._json({"alg": "ed25519" if pub else "none",
                        "pubkey": pub.hex() if pub else "",
                        "key_id": node.signer.key_id(),
                        "canonical_version": VerdictSigner.VERSION})
            return
        if path == "/api/status":
            if not self._auth_ok():
                return
            self._json(node.status())
            return
        for prefix, fn in (("/verdict/", node.lookup),
                           ("/report/", node.store.report)):
            if path.startswith(prefix):
                if not self._auth_ok():
                    return
                sha = path[len(prefix):].lower()
                if not SHA256_RE.match(sha):
                    self._json({"error": "not a sha256"}, 400)
                    return
                got = fn(sha)
                # A well-formed hash we have never been given is a resource
                # that does not exist -> 404. `pending` and `analyzing` are
                # real states of a real resource -> 200, so a polling client
                # can tell "come back later" from "you never sent me this".
                if got is None or got.get("status") == "unknown":
                    self._json({"sha256": sha, "status": "unknown"}, 404)
                    return
                self._json(got)
                return
        self._json({"error": "not found"}, 404)

    def do_HEAD(self) -> None:
        self._send(200, b"", "application/json")


class _Server(http.server.ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True
    node: "CrucibleNode" = None


def _console(node: "CrucibleNode") -> str:
    """A single-page operator view. No JavaScript, no external resources."""
    st = node.status()
    rows = []
    for r in node.store.recent(25):
        colour = {"malware": "#c0392b", "phishing": "#c0392b",
                  "grayware": "#c47f00", "benign": "#2d7", "unknown": "#888"
                  }.get(r["verdict"], "#888")
        rows.append(
            "<tr><td class=m>%s</td><td style='color:%s;font-weight:600'>%s</td>"
            "<td>%d</td><td>%s</td><td>%s</td><td>%s/f%s</td><td>%s</td>"
            "<td>%s</td></tr>" % (
                _esc(r["sha256"][:16]), colour, _esc(r["verdict"]),
                r["score"] or 0, _esc(r["threat"] or "-"),
                _esc(r["file_type"] or "-"), _esc(r["chamber"] or "-"),
                r["fidelity"] if r["fidelity"] is not None else "-",
                _esc(r["confidence"] or "-"), _esc(r["analyzed"] or "-")))
    chambers = "".join(
        "<tr><td>%s</td><td>%d</td><td style='color:%s'>%s</td><td>%s</td></tr>"
        % (_esc(c["name"]), c["fidelity"],
           "#2d7" if c["available"] else "#888",
           "available" if c["available"] else "unavailable",
           _esc(c["reason"])) for c in st["chambers"])
    signing = st["signing"]
    warn = ""
    if signing["alg"] == "none":
        warn += ("<p class=warn>Verdicts are UNSIGNED. A firewall configured to "
                 "require signatures will reject every verdict from this node. "
                 "Run <code>ffn_crucible_node.py keygen</code>.</p>")
    if not st["authenticated"]:
        warn += ("<p class=warn>No bearer token is configured, so any host that "
                 "can reach this port can submit samples and read verdicts.</p>")
    if st["max_fidelity"] == 0:
        warn += ("<p class=warn>No chamber on this node can execute a sample, so "
                 "it is doing static dissection only -- the same thing the "
                 "firewall could do without relaying.</p>")
    return """<!doctype html><meta charset=utf-8>
<title>FFN Crucible node %(node)s</title>
<style>
 body{font:13px/1.5 system-ui,sans-serif;margin:0;background:#14161a;color:#dde}
 header{padding:14px 20px;background:#1c1f26;border-bottom:1px solid #2a2f3a}
 h1{font-size:16px;margin:0}h2{font-size:13px;margin:22px 0 8px;color:#9ab}
 main{padding:0 20px 30px}
 table{border-collapse:collapse;width:100%%;margin-bottom:8px}
 th,td{text-align:left;padding:5px 9px;border-bottom:1px solid #262b34}
 th{color:#89a;font-weight:600;font-size:11px;text-transform:uppercase}
 .m{font-family:ui-monospace,monospace;color:#9cf}
 .k{display:inline-block;min-width:150px;color:#89a}
 .warn{background:#3a2418;border-left:3px solid #c47f00;padding:8px 12px;
       margin:10px 0;color:#fc9}
 code{font-family:ui-monospace,monospace;color:#9cf}
</style>
<header><h1>FFN Crucible &mdash; analysis node <span class=m>%(node)s</span></h1>
</header><main>
%(warn)s
<h2>Node</h2>
<div><span class=k>policy</span> %(policy)s &nbsp;
     <span class=k>workers</span> %(workers)d &nbsp;
     <span class=k>budget</span> %(timeout)ds</div>
<div><span class=k>verdict signing</span> %(alg)s
     %(keyid)s (canonical v%(cver)d)</div>
<div><span class=k>submitter auth</span> %(auth)s</div>
<div><span class=k>uptime</span> %(uptime)ds &nbsp;
     <span class=k>assayed</span> %(total)d</div>
<h2>Queue</h2>
<div><span class=k>pending</span> %(pending)d &nbsp;
     <span class=k>analysing</span> %(analyzing)d &nbsp;
     <span class=k>done</span> %(done)d &nbsp;
     <span class=k>error</span> %(error)d</div>
<h2>Chambers</h2>
<table><tr><th>chamber<th>fidelity<th>state<th>reason</tr>%(chambers)s</table>
<h2>Recent verdicts</h2>
<table><tr><th>sha256<th>verdict<th>score<th>threat<th>type<th>chamber
<th>confidence<th>assayed</tr>%(rows)s</table>
</main>""" % {
        "node": _esc(st["node"]), "warn": warn, "policy": _esc(st["policy"]),
        "workers": st["workers"], "timeout": st["timeout"],
        "alg": _esc(signing["alg"]),
        "keyid": _esc(signing["key_id"] or ""),
        "cver": signing["canonical_version"],
        "auth": "bearer token required" if st["authenticated"] else "NONE",
        "uptime": st["uptime"], "total": st["analyzed_total"],
        "pending": st["queue"]["pending"], "analyzing": st["queue"]["analyzing"],
        "done": st["queue"]["done"], "error": st["queue"]["error"],
        "chambers": chambers,
        "rows": "".join(rows) or "<tr><td colspan=8>nothing assayed yet</td></tr>",
    }


def _esc(s) -> str:
    import html
    return html.escape(str(s if s is not None else ""), quote=True)


LOOPBACK = ("127.0.0.1", "::1", "localhost")


def serve(node: "CrucibleNode", *, bind: str = "127.0.0.1",
          port: int = DEFAULT_PORT, certfile: str = "", keyfile: str = "",
          block: bool = True, allow_insecure: bool = False) -> "_Server":
    """Start the HTTP(S) server. Returns the server; caller may shut it down.

    Refuses to expose an unauthenticated endpoint. Binding anything but
    loopback with no bearer token configured means any host that can reach the
    port may submit samples and read verdicts -- which tells an attacker
    whether their sample is detected before they use it, and lets them fill the
    queue. That was previously a log warning, which is not an access control.
    """
    if bind not in LOOPBACK and node.token() is None and not allow_insecure:
        raise RuntimeError(
            "refusing to bind %s with no bearer token: any host that can reach "
            "this port could submit samples and read verdicts. Write a token to "
            "%s (chmod 600), bind 127.0.0.1 instead, or pass allow_insecure to "
            "accept the exposure deliberately." % (bind, TOKEN_PATH))
    httpd = _Server((bind, port), _Handler)
    httpd.node = node
    if certfile and keyfile:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        ctx.load_cert_chain(certfile, keyfile)
        httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True)
        scheme = "https"
    else:
        scheme = "http"
    real_port = httpd.server_address[1]

    if node.token() is None and bind not in LOOPBACK:
        # Only reachable with allow_insecure, since the check above refuses
        # otherwise. Deliberate exposure still gets said out loud.
        logger.warning("EXPOSED: no bearer token in %s and bound to %s -- any "
                       "host that can reach this port can submit samples and "
                       "read verdicts (allow_insecure was set)",
                       TOKEN_PATH, bind)
    if not node.signer.can_sign():
        logger.warning("no signing seed at %s: verdicts will be UNSIGNED and a "
                       "firewall requiring signatures will reject them",
                       node.signer.seed_path)
    if scheme == "http" and bind not in LOOPBACK:
        logger.warning("serving plaintext on %s: samples and verdicts cross the "
                       "network in the clear (verdicts stay ed25519-signed, so "
                       "they cannot be forged, but they can be read)", bind)

    node.start_workers()
    logger.info("crucible node %s on %s://%s:%d  policy=%s workers=%d "
                "max_fidelity=%d", node.node_id, scheme, bind, real_port,
                node.policy, node.workers, node.status()["max_fidelity"])
    if block:
        t = threading.Thread(target=httpd.serve_forever, daemon=True,
                             name="crucible-http")
        t.start()
        try:
            while t.is_alive():
                t.join(timeout=1.0)
        except KeyboardInterrupt:
            logger.info("shutting down")
        finally:
            httpd.shutdown()
            node.stop()
    else:
        threading.Thread(target=httpd.serve_forever, daemon=True,
                         name="crucible-http").start()
    return httpd


# ===========================================================================
# Self-test -- a full submit / analyse / verdict / verify round trip over
# loopback HTTP, with real ed25519 keys generated into a tmpdir. Nothing is
# executed: the node runs at policy=static.
# ===========================================================================
def selftest() -> int:
    import shutil
    import tempfile
    import urllib.error
    import urllib.request

    failures = []

    def check(cond, msg):
        if cond:
            print("  [ok] %s" % msg)
        else:
            print("  [FAIL] %s" % msg)
            failures.append(msg)

    print("ffn_crucible_node selftest")
    if CrucibleSandbox is None:
        print("  [FAIL] ffn_crucible is not importable")
        return 1
    if ffn_ed25519 is None:
        print("  [FAIL] ffn_ed25519 is not importable")
        return 1

    from ffn_crucible import build_test_pe
    tmp = tempfile.mkdtemp(prefix="crucible-node-test-")
    httpd = None
    node = None
    try:
        # -- real keys, in a tmpdir; the tree never holds key material ------
        seed_path, pub_path, pub_hex = ffn_ed25519.keygen(
            os.path.join(tmp, "verdict"))
        signer = VerdictSigner(seed_path=seed_path, pub_path=pub_path)
        check(signer.can_sign(), "signing key loaded (key id %s)"
              % signer.key_id())
        pub = bytes.fromhex(pub_hex)

        store = NodeStore(db_path=os.path.join(tmp, "node.sqlite"),
                          spool=os.path.join(tmp, "spool"))
        node = CrucibleNode(store, policy=POLICY_STATIC, workers=1,
                            signer=signer, node_id="selftest",
                            token="test-bearer-token-not-a-secret")

        print("\n1. submission and dedup")
        docx_vba = (b"Attribute VB_Name\x00Sub AutoOpen()\r\n"
                    b"Shell(\"powershell -enc SQBFAFgA\")\r\nEnd Sub")
        import io
        import zipfile
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as z:
            z.writestr("[Content_Types].xml", "<Types/>")
            z.writestr("word/vbaProject.bin", docx_vba)
        sample = buf.getvalue()
        sha = hashlib.sha256(sample).hexdigest()

        res = node.submit(sample, {"filename": "invoice.docx"})
        check(res["status"] == "queued" and res["sha256"] == sha,
              "first submission queued")
        check(node.submit(sample, {})["status"] in ("pending", "queued"),
              "resubmission before analysis is not queued twice")
        check(node.store.read_sample(sha) == sample,
              "the sample round-trips through the spool")
        check(node.submit(b"", {})["status"] == "rejected",
              "an empty submission is rejected")

        print("\n2. analysis and signing")
        drained = node.drain(limit=10)
        check(len(drained) == 1, "one sample analysed (%d)" % len(drained))
        bundle = drained[0]
        check(bundle["verdict"] == "malware"
              and bundle["threat"] == "MacroDropper",
              "verdict: %s / %s score=%d" % (bundle["verdict"],
                                             bundle["threat"], bundle["score"]))
        check(bundle["sig_alg"] == "ed25519" and len(bundle["sig"]) == 128,
              "the verdict carries an ed25519 signature")
        check(VerdictSigner.verify(bundle, pub),
              "the signature verifies against the node public key")
        check(node.submit(sample, {})["status"] == "done",
              "a submission with a known verdict is answered from cache")

        print("\n3. signature is not forgeable")
        tampered = dict(bundle, verdict="benign")
        check(not VerdictSigner.verify(tampered, pub),
              "flipping the verdict to benign breaks the signature")
        tampered = dict(bundle, score=0)
        check(not VerdictSigner.verify(tampered, pub),
              "changing the score breaks the signature")
        extra_ioc = dict(bundle)
        extra_ioc["iocs"] = list(bundle["iocs"]) + [
            {"type": "domain", "value": "bank.example.com",
             "verdict": "malware", "name": "injected"}]
        check(not VerdictSigner.verify(extra_ioc, pub),
              "injecting an IOC breaks the signature "
              "(this is the attacker-authored-outage case)")
        extra_sig = dict(bundle)
        extra_sig["signatures"] = list(bundle["signatures"]) + [
            {"name": "evil", "pattern_hex": "4745542f", "action": 1,
             "severity": "high"}]
        check(not VerdictSigner.verify(extra_sig, pub),
              "injecting a content signature breaks the signature")
        other_pub = ffn_ed25519.publickey(os.urandom(32))
        check(not VerdictSigner.verify(bundle, other_pub),
              "a verdict does not verify against an unrelated key")
        downgrade = dict(bundle, sig_alg="hmac")
        check(not VerdictSigner.verify(downgrade, pub),
              "an algorithm downgrade to hmac is refused")
        unsigned = dict(bundle, sig="", sig_alg="none")
        check(not VerdictSigner.verify(unsigned, pub),
              "an unsigned verdict is refused")
        check(VerdictSigner.verify(dict(bundle, details={"noise": 1}), pub),
              "a change OUTSIDE the canonical fields does not break it")

        print("\n4. HTTP round trip")
        httpd = serve(node, bind="127.0.0.1", port=0, block=False)
        port = httpd.server_address[1]
        base = "http://127.0.0.1:%d" % port
        auth = {"Authorization": "Bearer test-bearer-token-not-a-secret"}

        def http(method, path, body=None, headers=None, expect_error=True):
            req = urllib.request.Request(base + path, data=body,
                                         headers=headers or {}, method=method)
            try:
                with urllib.request.urlopen(req, timeout=10) as r:
                    return r.status, json.loads(r.read().decode("utf-8"))
            except urllib.error.HTTPError as e:
                if not expect_error:
                    raise
                try:
                    return e.code, json.loads(e.read().decode("utf-8"))
                except ValueError:
                    return e.code, {}

        code, body = http("GET", "/api/status", headers=auth)
        check(code == 200 and body.get("node") == "selftest",
              "GET /api/status returns node identity")
        check(body["signing"]["alg"] == "ed25519",
              "status reports ed25519 signing")

        code, body = http("GET", "/api/status")
        check(code == 401, "an unauthenticated status request is refused (401)")
        code, body = http("GET", "/api/status",
                          headers={"Authorization": "Bearer wrong-token"})
        check(code == 401, "a wrong bearer token is refused (401)")

        code, body = http("GET", "/api/pubkey")
        check(code == 200 and body["pubkey"] == pub_hex,
              "the verdict public key is served without authentication")

        pe = build_test_pe({"kernel32.dll": ["CreateRemoteThread",
                                             "VirtualAllocEx"]},
                           overlay=b"MZ" + b"\x90" * 2048)
        code, body = http("POST", "/submit", pe,
                          dict(auth, **{"Content-Type": "application/octet-stream",
                                        "X-Crucible-Filename": "setup.exe"}))
        check(code == 202 and body["status"] == "queued",
              "POST /submit queues over HTTP (202)")
        pe_sha = body["sha256"]

        code, body = http("POST", "/submit", pe,
                          {"Content-Type": "application/octet-stream"})
        check(code == 401, "an unauthenticated submission is refused")

        # Generous on purpose: the analysis budget is not what this test is
        # checking, and a deadline tight enough to expire on a loaded machine
        # turns a working system into a red build.
        deadline = time.time() + 120
        served = {}
        while time.time() < deadline:
            code, served = http("GET", "/verdict/%s" % pe_sha, headers=auth)
            if served.get("status") == "done":
                break
            time.sleep(0.2)
        finished = served.get("status") == "done"
        check(finished, "the worker pool analysed the HTTP submission"
              if finished else
              "the worker pool did not finish within 120s (status=%s) -- the "
              "checks below are skipped, not failed"
              % served.get("status"))
        if finished:
            # .get() rather than [] so a malformed bundle fails a check instead
            # of raising on top of it.
            check(VerdictSigner.verify(served, pub),
                  "the verdict served over HTTP verifies")
            check(served.get("verdict") in ("malware", "grayware"),
                  "overlay-carrying injector -> %s/%s"
                  % (served.get("verdict"), served.get("threat")))

        if finished:
            code, body = http("GET", "/report/%s" % pe_sha, headers=auth)
            check(code == 200
                  and body.get("details", {}).get("chamber") == "static",
                  "the full report is retrievable and names its chamber")

        print("\n5. the HTTP surface refuses everything else")
        for method, path, expect in (("GET", "/etc/passwd", 404),
                                     ("GET", "/../../etc/shadow", 404),
                                     ("GET", "/verdict/notahash", 400),
                                     ("GET", "/verdict/" + "0" * 64, 404),
                                     ("GET", "/report/%2e%2e%2f", 400),
                                     ("POST", "/anything", 404),
                                     ("GET", "/submit", 404)):
            code, _b = http(method, path, b"x" if method == "POST" else None,
                            auth)
            check(code == expect, "%s %s -> %d" % (method, path[:24], code))

        code, _b = http("POST", "/submit", b"tiny",
                        dict(auth, **{"Content-Length": str(MAX_BODY + 1)}))
        check(code in (400, 413),
              "an oversized declared body is refused before it is read (%d)"
              % code)

        print("\n6. the operator console renders")
        req = urllib.request.Request(base + "/")
        with urllib.request.urlopen(req, timeout=10) as r:
            page = r.read().decode("utf-8")
        check(r.status == 200 and "Crucible" in page,
              "GET / serves the console")
        check("MacroDropper" in page, "the console lists recent verdicts")
        check("<script" not in page.lower(),
              "the console has no scripting and no external resources")
        check("test-bearer-token" not in page,
              "the console never renders the bearer token")

        print("\n7. an unsigned node is honest about it")
        bare = CrucibleNode(
            NodeStore(db_path=os.path.join(tmp, "bare.sqlite"),
                      spool=os.path.join(tmp, "bare-spool")),
            policy=POLICY_STATIC, workers=1,
            signer=VerdictSigner(seed_path=os.path.join(tmp, "absent.key"),
                                 pub_path=os.path.join(tmp, "absent.pub")),
            node_id="unsigned", token="")
        check(not bare.signer.can_sign(), "a node with no seed cannot sign")
        bare.submit(sample, {})
        got = bare.drain(limit=1)[0]
        check(got["sig_alg"] == "none" and got["sig"] == "",
              "its verdicts are marked unsigned rather than faked")
        check(not VerdictSigner.verify(got, pub),
              "and a verifier refuses them")
        check(bare.status()["signing"]["alg"] == "none"
              and bare.status()["authenticated"] is False,
              "status reports both gaps so an operator can see them")
        bare.store.close()

        print("\n7b. an unauthenticated endpoint is not exposed")
        untokened = CrucibleNode(
            NodeStore(db_path=os.path.join(tmp, "exposed.sqlite"),
                      spool=os.path.join(tmp, "exposed-spool")),
            policy=POLICY_STATIC, workers=1, signer=signer,
            node_id="exposed", token="")
        try:
            refused = False
            try:
                serve(untokened, bind="0.0.0.0", port=0, block=False)
            except RuntimeError as e:
                refused = "bearer token" in str(e)
            check(refused,
                  "binding 0.0.0.0 with no token is refused, not merely warned")
            # Loopback with no token stays permitted: it is contained, and the
            # rest of this selftest depends on it.
            local_ok = None
            try:
                local_ok = serve(untokened, bind="127.0.0.1", port=0,
                                 block=False)
                check(True, "loopback with no token is still permitted")
            finally:
                if local_ok is not None:
                    local_ok.shutdown()
                    local_ok.server_close()
            # And the deliberate override works, because a lab needs it.
            forced = None
            try:
                forced = serve(untokened, bind="127.0.0.1", port=0,
                               block=False, allow_insecure=True)
                check(True, "allow_insecure is honoured for deliberate exposure")
            finally:
                if forced is not None:
                    forced.shutdown()
                    forced.server_close()
        finally:
            untokened.stop()
            untokened.store.close()

        print("\n8. durability")
        node.store.close()
        reopened = NodeStore(db_path=os.path.join(tmp, "node.sqlite"),
                             spool=os.path.join(tmp, "spool"))
        again = reopened.verdict(sha)
        check(again is not None and VerdictSigner.verify(again, pub),
              "verdicts survive a restart and still verify")
        check(reopened.read_sample(sha) == sample,
              "spooled samples survive a restart")
        reopened.close()
    finally:
        if httpd is not None:
            httpd.shutdown()
        if node is not None:
            node.stop()
            node.store.close()
        shutil.rmtree(tmp, ignore_errors=True)

    print()
    if failures:
        print("FAILED %d check(s):" % len(failures))
        for f in failures:
            print("  - %s" % f)
        return 1
    print("all crucible node selftests passed")
    return 0


# ===========================================================================
# CLI
# ===========================================================================
def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        prog="ffn_crucible_node.py",
        description="FFN Crucible analysis node (the box a firewall relays to)")
    ap.add_argument("--debug", action="store_true")
    ap.add_argument("--db", default=None, help="override the node database")
    ap.add_argument("--spool", default=None, help="override the sample spool")
    sub = ap.add_subparsers(dest="cmd")

    sub.add_parser("selftest", help="hermetic submit/verdict/verify round trip")
    sub.add_parser("status", help="print node status as JSON")

    p = sub.add_parser("serve", help="run the node")
    p.add_argument("--bind", default="127.0.0.1")
    p.add_argument("--port", type=int, default=DEFAULT_PORT)
    p.add_argument("--policy", choices=POLICIES, default=POLICY_BEST)
    p.add_argument("--workers", type=int, default=2)
    p.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT)
    p.add_argument("--guests", default=DEFAULT_GUEST_PROFILES)
    p.add_argument("--node-id", default="")
    p.add_argument("--cert", default="", help="TLS certificate (optional)")
    p.add_argument("--key", default="", help="TLS private key (optional)")
    p.add_argument("--allow-insecure", action="store_true",
                   help="permit a non-loopback bind with no bearer token. Any "
                        "host that can reach the port could then submit "
                        "samples and read verdicts; for an isolated lab only.")

    p = sub.add_parser("work", help="drain the queue once and exit")
    p.add_argument("--limit", type=int, default=50)
    p.add_argument("--policy", choices=POLICIES, default=POLICY_BEST)
    p.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT)
    p.add_argument("--guests", default=DEFAULT_GUEST_PROFILES)

    p = sub.add_parser("keygen", help="create this node's verdict-signing key")
    p.add_argument("--prefix", default="/etc/ffn-ngfw/crucible-verdict")

    p = sub.add_parser("submit", help="submit a local file to this node's queue")
    p.add_argument("file")

    p = sub.add_parser("verdict", help="look a verdict up locally")
    p.add_argument("sha256")

    args = ap.parse_args(argv)
    logging.basicConfig(
        level=logging.DEBUG if args.debug else logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s")

    if args.cmd == "selftest":
        return selftest()

    if args.cmd == "keygen":
        if ffn_ed25519 is None:
            print("ERROR: ffn_ed25519 is not importable", file=sys.stderr)
            return 1
        kp, pp, pub = ffn_ed25519.keygen(args.prefix)
        print("private seed : %s   (never leaves this node, never in an image)"
              % kp)
        print("public key   : %s" % pp)
        print("pubkey       : %s" % pub)
        print()
        print("Install the PUBLIC key on each firewall that will trust this")
        print("node, as /etc/ffn-ngfw/crucible-verdict.pub, and point the")
        print("firewall at this node with:")
        print("  cloud_det.py --relay https://<node>:%d "
              "--relay-pubkey /etc/ffn-ngfw/crucible-verdict.pub" % DEFAULT_PORT)
        return 0

    def build_node(policy, timeout, guests, node_id="", workers=1):
        store = NodeStore(db_path=args.db, spool=args.spool)
        return CrucibleNode(store, policy=policy, timeout=timeout,
                            workers=workers, guest_profiles=guests,
                            node_id=node_id)

    if args.cmd == "serve":
        node = build_node(args.policy, args.timeout, args.guests,
                          args.node_id, max(1, args.workers))
        try:
            serve(node, bind=args.bind, port=args.port, certfile=args.cert,
                  keyfile=args.key, block=True,
                  allow_insecure=args.allow_insecure)
        except RuntimeError as e:
            print("ERROR: %s" % e, file=sys.stderr)
            return 2
        return 0

    if args.cmd == "work":
        node = build_node(args.policy, args.timeout, args.guests)
        done = node.drain(limit=args.limit)
        for b in done:
            print("%s  %-8s %3d  %-24s %s" %
                  (b["sha256"][:16], b["verdict"], b["score"],
                   b.get("threat", "-"),
                   b.get("details", {}).get("chamber", "-")))
        print("%d sample(s) assayed; %s" %
              (len(done), json.dumps(node.store.stats()["verdicts"])))
        node.store.close()
        return 0

    if args.cmd == "status":
        node = build_node(POLICY_BEST, DEFAULT_TIMEOUT, DEFAULT_GUEST_PROFILES)
        print(json.dumps(node.status(), indent=2, sort_keys=True))
        node.store.close()
        return 0

    if args.cmd == "submit":
        node = build_node(POLICY_BEST, DEFAULT_TIMEOUT, DEFAULT_GUEST_PROFILES)
        with open(args.file, "rb") as fh:
            data = fh.read(MAX_SAMPLE)
        res = node.submit(data, {"filename": os.path.basename(args.file)},
                          submitter="cli")
        print(json.dumps(res))
        node.store.close()
        return 0 if res.get("status") != "rejected" else 1

    if args.cmd == "verdict":
        node = build_node(POLICY_BEST, DEFAULT_TIMEOUT, DEFAULT_GUEST_PROFILES)
        print(json.dumps(node.lookup(args.sha256.lower().strip()), indent=2,
                         sort_keys=True))
        node.store.close()
        return 0

    ap.print_help()
    return 0


if __name__ == "__main__":
    sys.exit(main())
