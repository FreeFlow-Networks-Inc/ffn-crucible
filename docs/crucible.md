# Crucible — unknown-object detonation

A crucible is a sealed vessel you fire an unknown object in to find out what it
actually is. This is the subsystem that does that to the files FFN carves out of
live traffic: it detonates them, watches what they do, and converts the
behaviour into content the firewall can enforce.

It is the **unknown**-threat half of the detection stack. The known half
(`inline_payload_det.py`) enforces at line rate what is already known. Crucible
is what makes something known in the first place.

```
  inline_payload_det.carve_files()      unknown PE / ELF / doc / script
              |
              v
  CloudDetectionService.submit()        dedup against the verdict cache,
              |                         spool to a durable pending row
              v
  QueueDrainer  (off the datapath)      one drainer per appliance
              |
              v
  a backend:  CrucibleSandbox           on-box: static -> jail -> guest VM
           or RelayBackend              offload to a Crucible node
              |
              v
  BehaviorTrace -> Assay                weighted behaviour rules
              |
              v
  verdict + IOCs + generated signatures
              |
     +--------+---------+------------------+
     |                  |                  |
  ThreatDB.samples   ThreatDB.iocs   inline.add_signature
  (hash blocklist)   (C2 infra)      (variant coverage)
     |                  |                  |
     +--------- compile_to_fpga() ---------+
                        |
                        v
              hardware fast path
```

The next appearance of that file (by hash), of its infrastructure (by IOC), or
of a re-packed variant (by generated signature) is blocked — in software
immediately, and in the FPGA after the compile push.

## The three deployment shapes

A firewall is a bad place to detonate malware: no spare cores, no hypervisor, an
uptime requirement, and a sandbox escape on the device that enforces your policy
is the worst possible outcome. So analysis is offloadable.

| Shape | Configure with | What you get |
|---|---|---|
| **on-box** | `--backend local` | No node, no network. Static dissection by default; `--policy jail` adds real execution on the appliance. |
| **relay** | `--backend relay:https://node:8449` | Guest-VM fidelity without hosting a hypervisor. If the node is down, objects stay queued and get no verdict. |
| **relay + local** | `--backend relay+local:https://node:8449` | As above, but falls back to on-box analysis when the node is unreachable. **Recommended:** an outage degrades fidelity instead of stopping inspection. |

Same engine in all three; only the arrangement changes.

## Chambers

The engine uses the highest-fidelity chamber that can actually run the sample,
and every report says which one ran. A chamber that cannot run declares itself
unavailable *with a reason* rather than silently producing a weaker verdict —
`ffn_crucible.py chambers` prints exactly what this box can do.

| Fidelity | Chamber | Executes | What it does |
|---|---|---|---|
| 0 | `static` | no | Real format dissection: PE section and import tables, ELF program headers and dynamic symbols, OOXML/OLE macro detection, PDF action objects, one layer of base64/UTF-16 deobfuscation. Always available. |
| 1 | `jail` | **yes** | Runs native-arch samples under `unshare` in mount/PID/network namespaces, traced with `strace`, with the scratch filesystem diffed for dropped files. |
| 2 | `qemu` | **yes** | Restores a throwaway guest VM, injects the sample, and reads observations back over virtio-serial. The only chamber that can run a Windows PE or an Office macro, and the only one that is a real containment boundary. |

### Policy: nothing executes by default

`--policy static` is the default, and it never executes a sample. Enabling a
live chamber is an explicit operator decision — an appliance must not start
executing objects carved out of customer traffic because someone deployed an
update.

### What `jail` is and is not

With `--map-root-user` we are root *inside* the new namespaces without being
root outside. That is what makes the design work unprivileged: we can bring up
loopback and bind ports 53/80/443 in the new network namespace, so the fake
internet runs **inside the jail** on 127.0.0.1 and the sample can reach it,
while the jail has no route to anything real. We can also bind-mount a
`resolv.conf` over `/etc/resolv.conf` in the new mount namespace without
touching the host's.

**It is an observation chamber, not a containment boundary.** Without a
`jail_root` the host filesystem is still visible, and a sample written to escape
a user namespace may succeed. Run it on a box you are willing to rebuild, give
it a `jail_root`, or use `qemu` for samples you have reason to fear.

## The sinkhole

A sample that cannot resolve or connect anywhere fails early and its interesting
behaviour never happens. A sample given the real internet attacks third parties
from your address and shows its operator that it is being analysed. So Crucible
gives it a fake internet: every name resolves to us, every connection is
accepted, and the answers are plausible.

That is where the good indicators come from. A syscall trace tells you a sample
connected to an address; the sinkhole tells you the **DNS name** it asked for,
the full **HTTP request line**, its **Host** and **User-Agent**, and the **TLS
SNI** — which are the artefacts a signature can actually be built from.

`ffn_crucible.py sinkhole` runs it standalone if you want to point something at
it by hand.

## Evidence provenance, and why it decides the verdict

Every observation records where it came from, and that is what sets its weight:

| Source | Meaning | Weight |
|---|---|---|
| `runtime` | The sample did this. | full |
| `content` | The object's own content asserts it — a shell script that says `curl … \| sh`, a macro that says `Shell()`, a UPX section. The code *is* the behaviour. | full |
| `import` | An import table or dynamic-symbol entry. Says what the code *could* do. | discounted |

This distinction is load-bearing. Half of Windows imports `VirtualAllocEx`, so
an import table full of injection APIs is suspicion, not proof: such a sample
comes back **grayware with low confidence**, and stays queued for a live
chamber. A shell script whose source says `curl … -o /tmp/p; chmod +x; /tmp/p`
is convicted on content alone, because there is nothing left to interpret.

Rules are **combinations**, never single indicators — single indicators are how
sandboxes generate false positives. "Allocated memory in another process *and*
wrote to it *and* started a thread there" describes an injector and almost
nothing else.

### `unknown` is a real verdict

Static inspection alone will not call an executable benign. That claim is the
false negative that gets someone owned, so a quiet PE with nothing found comes
back `unknown`, which keeps it queued for a better chamber instead of caching a
clean verdict for a week. Detonation *can* clear it — a benign ELF that runs and
does nothing interesting is reported benign.

## Generated content, and the guard against self-harm

A convicted sample yields three enforceable things: its **hash**, its
**infrastructure**, and **content signatures** built from its own runtime
artefacts (an odd User-Agent, a beacon URI path, a dropped filename).

Two safeguards matter here, because both failure modes are outages we would
cause ourselves:

* **The analysis network is never blocklisted.** The sinkhole answers every
  lookup with its own address and SLIRP hands the guest `10.0.2.x`. Reserved and
  loopback addresses are filtered out of every IOC — `127.0.0.1` in a blocklist
  pushed to the FPGA would be a self-inflicted outage.
* **Format and PKI infrastructure is never blocklisted.** A `.docx` carries
  `schemas.openxmlformats.org`, a PDF carries `ns.adobe.com`, a signed binary
  carries its CA's OCSP and CRL hosts. Those are allowlisted narrowly —
  standards and PKI only, never general CDNs or code-hosting, because payload
  staging on those is commonplace and allowlisting them would create exactly the
  blind spot an attacker would pick.

Signatures are also never built from an import symbol name. A content rule
matching `CreateRemoteThread` fires on the import directory of every legitimate
binary that calls it.

## Verdict signing

A verdict is not advice, it is an instruction: it makes the firewall blocklist a
hash, condemn a domain, and install a DROP rule that is then pushed into the
FPGA fast path. Anyone who can forge one can either clear a sample they want
delivered, or blocklist a domain they want taken down — a denial of service
authored by the attacker and executed by your own hardware.

So every verdict a node returns is **ed25519-signed** over a canonical
serialisation, and the firewall refuses one that does not verify against a
pinned key. TLS is not a substitute: it authenticates the connection, not the
verdict, and the verdict outlives the connection — it is cached, relayed and
replayed from the database.

The canonical form covers exactly the fields the firewall acts on, so adding a
diagnostic field to a report later cannot invalidate existing signatures, and a
verifier can tell precisely what it is trusting. It is defined once, in
`ffn_crucible.VerdictSigner`, and both ends import that definition.

The private seed lives only on the node and is never packaged into an image
(`tools/PUBLISH-POLICY`).

## Failure is `unknown`, never `benign`

A node that is unreachable, slow, or unverifiable yields `unknown`. The sample
stays queued and the inline engine keeps enforcing what it already knows.
Returning `benign` on an error would cache a clean verdict for a week for a file
nobody ever looked at.

## Setting it up

### On the appliance

```bash
# what can this box actually do?
python3 /opt/ffn-ngfw-v2/ffn_crucible.py chambers

# what backend does the current configuration build?
python3 /opt/ffn-ngfw-v2/cloud_det.py --backend relay+local:https://node:8449 backend
```

Datapath configuration lives in `DataplaneConfig` (`ffn_bmfw.py`):
`crucible_backend`, `crucible_policy`, `crucible_timeout`,
`crucible_relay_token`, `crucible_relay_pubkey`, `crucible_drain`.

`crucible_drain` must stay on. Without a drainer the datapath spools every
carved object to a pending row and nothing ever analyses it.

### On the node

```bash
# one-time: create the verdict-signing key
python3 ffn_crucible_node.py keygen --prefix /etc/ffn-ngfw/crucible-verdict

# a bearer token for submitters
head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n' > /etc/ffn-ngfw/crucible-node.token
chmod 600 /etc/ffn-ngfw/crucible-node.token

# run it
python3 ffn_crucible_node.py serve --bind 0.0.0.0 --port 8449 \
    --policy best --workers 2 --cert /etc/ffn-ngfw/node.crt --key /etc/ffn-ngfw/node.key
```

Then install `crucible-verdict.pub` and the token on each firewall that will
trust this node. The node's own console at `https://node:8449/` shows queue
depth, chamber availability, recent verdicts, and warns when it is unsigned or
unauthenticated.

See [crucible-guest-image.md](crucible-guest-image.md) to build the guest that
the `qemu` chamber needs.

## Self-tests

All three are hermetic — nothing is executed, nothing leaves loopback:

```bash
python3 ffn_crucible.py selftest        # dissectors, sinkhole, assay, IOC safety
python3 ffn_crucible_node.py selftest   # submit/verdict/verify round trip, forgery
python3 cloud_det.py selftest               # in FFN-NGFW: the closed loop, drainer, offload
```

To exercise a live chamber you need a Linux host with `unshare` and `strace`:

```bash
python3 ffn_crucible.py detonate --chamber jail --timeout 20 ./sample
python3 ffn_crucible.py assay --policy jail ./sample
```

## Files

In THIS repository:

| File | Role |
|---|---|
| `ffn_crucible.py` | The engine: dissectors, chambers, sinkhole, assay, `VerdictSigner` |
| `ffn_crucible_node.py` | The analysis node: queue, workers, signed-verdict API, console |
| `ffn_ed25519.py` | Dependency-free ed25519 (RFC 8032); duplicated from FFN-NGFW so the node stands alone |
| `docs/crucible-guest-image.md` | How to build a guest for the `qemu` chamber |
| `units/ffn-crucible-node.service` | systemd unit for a dedicated analysis node |
| `tools/PUBLISH-POLICY` | What may never be committed here; enforced by `tools/publish-check.py` |

In [FFN-NGFW](https://github.com/FreeFlow-Networks-Inc/FFN-NGFW), which
consumes this repository as a submodule at `crucible/`:

| File | Role |
|---|---|
| `opt/cloud_det.py` | Firewall side: submission, dedup, `RelayBackend`, `FallbackBackend`, `QueueDrainer`, enforcement wiring |
| `opt/inline_payload_det.py` | Carving and inline enforcement (the known half) |
| `opt/ffn_threatdb.py` | Sample verdicts, IOCs, signatures; FPGA region export |
| `opt/ffn_bmfw.py` | The data plane that carves objects and starts the drainer |
| `opt/ffn_manager.py` | `/api/crucible/status` for the WebUI |
