# FFN Crucible

A crucible is a sealed vessel you fire an unknown object in to find out what it
actually is. This is that vessel: an **offloadable malware-detonation engine**
that takes unknown files, runs them under observation, and turns what they *do*
into content a firewall can enforce.

It is the unknown-threat half of [FFN-NGFW](https://github.com/FreeFlow-Networks-Inc/FFN-NGFW)'s
detection stack, and is consumed there as a submodule at `crucible/`. It also
runs standalone as an analysis node that any number of firewalls can relay to.

FFN's own code, no third-party runtime. Everything here runs on a **bare
python3** with no pip modules — that is a property of the appliance this ships
on, and CI enforces it.

```
        unknown file
             |
             v
    +--------------------+     static     dissect the format, never execute
    |     chambers       |     jail       execute in namespaces, traced
    +--------------------+     qemu       execute in a throwaway guest VM
             |
             v
      BehaviorTrace            typed observations, not strings
             |
             v
         the assay             weighted behaviour rules
             |
             v
   verdict + IOCs + signatures
```

## What it produces

A convicted sample yields three enforceable things:

- a **hash verdict**, which blocks that exact file;
- **network IOCs**, which block the infrastructure it uses — this is what
  covers the variants;
- **content signatures** built from its own runtime artefacts (an odd
  User-Agent, a beacon URI path, a dropped filename), which catch the next
  build of the same family after its hash changes.

## The chambers

The engine uses the highest-fidelity chamber that can actually run the sample,
and every report says which one ran. A chamber that cannot run declares itself
unavailable **with a reason** rather than silently producing a weaker verdict.

| Fidelity | Chamber | Executes | |
|---|---|---|---|
| 0 | `static` | no | Real format dissection: PE section and import tables, ELF program headers and dynamic symbols, OOXML/OLE macro detection, PDF action objects, one layer of base64/UTF-16 deobfuscation. Always available. |
| 1 | `jail` | **yes** | Native-arch samples under `unshare` in mount/PID/network namespaces, traced with `strace`, scratch filesystem diffed for dropped files. |
| 2 | `qemu` | **yes** | A throwaway guest VM. The only chamber that can run a Windows PE or an Office macro, and the only one that is a real containment boundary. Needs a prepared guest — see [docs/crucible-guest-image.md](docs/crucible-guest-image.md). |

```bash
python3 ffn_crucible.py chambers     # what this box can actually run
```

**Nothing executes by default.** `--policy static` is the default and never
runs a sample; enabling a live chamber is an explicit operator decision.

## The fake internet

A sample that cannot resolve or connect anywhere fails early and its
interesting behaviour never happens. A sample given the *real* internet attacks
third parties from your address and shows its operator it is being analysed. So
Crucible gives it a fake one: every name resolves to us, every connection is
accepted, and the answers are plausible.

That is where the good indicators come from. A syscall trace says a sample
connected to an address; the sinkhole gives you the **DNS name** it asked for,
the full **HTTP request line**, its **Host** and **User-Agent**, and the **TLS
SNI** — the artefacts a signature can actually be built from.

In the `jail` chamber this runs *inside* the jail's own network namespace, on
its loopback, with no host privileges and no route to anything real. Under
`qemu` the guest is fully isolated (`restrict=on`) and indicators are recovered
from a packet capture instead.

```bash
python3 ffn_crucible.py sinkhole     # run the capture service standalone
```

## Evidence provenance

Every observation records where it came from, and that sets its weight:

| Source | Meaning | Weight |
|---|---|---|
| `runtime` | The sample did this. | full |
| `content` | The object's own content asserts it — a script that says `curl … \| sh`, a macro that says `Shell()`, a UPX section. The code *is* the behaviour. | full |
| `import` | An import table entry. Says what the code *could* do. | discounted |

This distinction is load-bearing. Half of Windows imports `VirtualAllocEx`, so
an import table full of injection APIs is suspicion, not proof: such a sample
comes back **grayware, low confidence**, and stays queued for a live chamber. A
shell script whose source says `curl … -o /tmp/p; chmod +x; /tmp/p` is convicted
on content alone, because there is nothing left to interpret.

Rules are **combinations**, never single indicators — single indicators are how
sandboxes generate false positives. "Allocated memory in another process *and*
wrote to it *and* started a thread there" describes an injector and almost
nothing else.

### `unknown` is a real verdict

Static inspection alone will not call an executable benign. That claim is the
false negative that gets someone owned, so a quiet PE with nothing found comes
back `unknown` — which keeps it queued for a better chamber instead of caching
a clean verdict for a week. Detonation *can* clear it.

## Offload: the analysis node

A firewall is a bad place to detonate malware — no spare cores, no hypervisor,
an uptime requirement, and a sandbox escape on the device that enforces your
policy is the worst possible outcome. So `ffn_crucible_node.py` runs the
engine on a separate box that firewalls relay to.

```bash
python3 ffn_crucible_node.py keygen --prefix /etc/ffn-ngfw/crucible-verdict
head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n' > /etc/ffn-ngfw/crucible-node.token
chmod 600 /etc/ffn-ngfw/crucible-node.token

python3 ffn_crucible_node.py serve --bind 0.0.0.0 --port 8449 \
    --policy best --workers 2 --cert node.crt --key node.key
```

| Endpoint | |
|---|---|
| `POST /submit` | sample bytes, bearer token → `{sha256, status}` |
| `GET /verdict/<sha256>` | the **signed** verdict, or `{status: pending}` |
| `GET /report/<sha256>` | the full behaviour report |
| `GET /api/status` | queue depth, chamber availability, signing state |
| `GET /api/pubkey` | this node's verdict-signing public key |
| `GET /` | operator console |

Nothing else is reachable. This is not a file server.

### Verdicts are signed, and that is not decoration

A verdict is not advice, it is an instruction: it makes a firewall blocklist a
hash, condemn a domain, and install a DROP rule. Anyone who can forge one can
either clear a sample they want delivered, or blocklist a domain they want taken
down — a denial of service authored by the attacker and executed by the
defender's own hardware.

So every verdict is **ed25519-signed** over a canonical serialisation, and a
client refuses one that does not verify against a pinned key. TLS is not a
substitute: it authenticates the connection, not the verdict, and the verdict
outlives the connection — it is cached, relayed and replayed from a database.

The canonical form covers exactly the fields a client acts on, so adding a
diagnostic field to a report later cannot invalidate existing signatures, and a
verifier can tell precisely what it is trusting.

**The private seed never leaves the node and is never packaged into an image.**

### Failure is `unknown`, never `benign`

A node that is unreachable, slow, or unverifiable yields `unknown`. The sample
stays queued and the client keeps enforcing what it already knows. Returning
`benign` on an error would cache a clean verdict for a week for a file nobody
ever looked at.

## Guards against self-harm

Two failure modes here are outages you would cause yourself, so both are
handled explicitly:

- **The analysis network is never blocklisted.** The sinkhole answers every
  lookup with its own address and SLIRP hands the guest `10.0.2.x`. Reserved
  and loopback addresses are filtered out of every IOC — `127.0.0.1` in a
  blocklist pushed to a hardware fast path would be self-inflicted.
- **Format and PKI infrastructure is never blocklisted.** A `.docx` carries
  `schemas.openxmlformats.org`, a PDF carries `ns.adobe.com`, a signed binary
  carries its CA's OCSP and CRL hosts. Those are allowlisted narrowly —
  standards and PKI only, never general CDNs or code-hosting, because payload
  staging on those is commonplace and allowlisting them would create exactly
  the blind spot an attacker would pick.

Signatures are also never built from an import symbol name: a content rule
matching `CreateRemoteThread` fires on the import directory of every legitimate
binary that calls it.

## Self-tests

Hermetic — nothing is executed, nothing leaves loopback:

```bash
python3 ffn_ed25519.py --selftest        # RFC 8032 vectors + negative cases
python3 ffn_crucible.py selftest         # dissectors, sinkhole, assay, IOC safety
python3 ffn_crucible_node.py selftest    # submit/verdict/verify round trip, forgery
```

To exercise a live chamber you need Linux with `unshare` and `strace`:

```bash
python3 ffn_crucible.py detonate --chamber jail --timeout 20 ./sample
python3 ffn_crucible.py assay --policy jail ./sample
```

## Layout

| Path | |
|---|---|
| `ffn_crucible.py` | The engine: dissectors, chambers, sinkhole, pcap parser, assay, `VerdictSigner` |
| `ffn_crucible_node.py` | The analysis node: queue, workers, signed-verdict API, console |
| `ffn_ed25519.py` | Dependency-free ed25519 (RFC 8032). See *Shared code* below. |
| `docs/crucible.md` | Design, deployment shapes, setup |
| `docs/crucible-guest-image.md` | The `qemu` chamber's guest contract |
| `units/ffn-crucible-node.service` | systemd unit for a dedicated node |

### Shared code

`ffn_ed25519.py` is byte-identical to FFN-NGFW's copy, and deliberately
duplicated rather than imported: the node cannot sign a verdict without it, and
a signing engine that depends on the firewall repo being checked out beside it
would not stand alone. Drift is detectable rather than theoretical — it
implements RFC 8032, whose test vectors are frozen, and
`ffn_ed25519.py --selftest` checks them in both repos' CI.

`ffn_crucible.py` soft-imports `inline_payload_det` and `ffn_threatdb` from
FFN-NGFW when they are present, and falls back to equivalent local definitions
when they are not — so it behaves identically standalone and in-tree.

## Licence

GPL-2.0-or-later. See [LICENSE](LICENSE).

## A note on what this is for

Crucible executes malware on purpose. The `jail` chamber is an **observation**
chamber, not a containment boundary: without a chroot the host filesystem is
still visible, and a sample written to escape a user namespace may succeed. Run
it on a box you are willing to rebuild, or use the `qemu` chamber, which is a
real boundary. Do not run a live chamber on a firewall.
