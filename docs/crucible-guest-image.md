# Building a guest for the Crucible `qemu` chamber

The `qemu` chamber is the only one that can run a Windows PE or an Office macro,
and the only one that is a real containment boundary. It needs a prepared guest
image, which an appliance does not ship — so until you build one it reports
itself unavailable, with the reason, and the engine falls back to a lower
fidelity.

Nothing about the guest OS is assumed beyond the contract below. If your agent
speaks it, the chamber does not care what is running inside.

## The contract

1. A **qcow2** the guest boots unattended to a logged-in session, with no
   prompts, no updates on boot, and no screen lock.
2. The **guest agent** runs at logon.
3. The agent finds its work on the read-only FAT volume the chamber attaches
   with serial `CRUCIBLE`:
   - `crucible.json` — `{"sample": "<filename>", "sha256": …, "timeout": <seconds>, "file_type": …}`
   - the sample itself, under the name `crucible.json` gives.
4. The agent writes **newline-delimited JSON** observations to the virtio-serial
   port named `ffn.crucible.0`.
5. The agent writes a final `{"done": true}` line. That is how the host knows
   the run finished rather than the budget expiring.

## The observation format

One JSON object per line, in Crucible's own vocabulary — so a new guest OS needs
no host-side changes, only an agent that speaks it:

```json
{"kind":"process","what":"exec","detail":"started notepad.exe","value":"notepad.exe"}
{"kind":"file","what":"write","detail":"wrote into the profile","value":"C:\\Users\\u\\AppData\\Roaming\\x.exe"}
{"kind":"registry","what":"persist_reg","detail":"Run key written","value":"HKCU\\...\\Run\\Updater"}
{"kind":"net","what":"dns_query","detail":"resolved","value":"beacon.example.invalid"}
{"kind":"capability","what":"proc_inject","detail":"WriteProcessMemory into explorer.exe","value":"explorer.exe"}
{"kind":"capability","what":"mutex","detail":"created a named mutex","value":"Global\\zX91"}
{"kind":"persist","what":"persist_task","detail":"scheduled task created","value":"UpdaterTask"}
{"kind":"evade","what":"evade_vm","detail":"queried the SMBIOS table"}
{"kind":"file","what":"dropped","detail":"stage two","value":"x.exe",
 "dropped":{"name":"x.exe","size":40960,"sha256":"…","type":"pe"}}
{"done":true}
```

Fields:

| Field | Meaning |
|---|---|
| `kind` | One of `meta`, `capability`, `process`, `file`, `registry`, `net`, `persist`, `evade`, `crypto`. An unrecognised kind is kept as `capability` rather than dropped, so a future agent extension degrades instead of vanishing. |
| `what` | The stable token the assay reasons about. See `CAPABILITY` and `TOKEN_WEIGHT` in `ffn_crucible.py` for the ones that carry weight. |
| `detail` | Free text for the operator. Not scored. |
| `value` | The artefact itself — a path, a host, a mutex name. **This is what signatures get built from**, so report the real thing rather than a description of it. |
| `dropped` | Optional; attaches a dropped-file record to the observation. |

Everything the agent reports is treated as **runtime** evidence, because the
agent only speaks about things that happened. That is the strongest class the
assay has, so do not report static guesses through this channel — a string found
in the sample is not an observation of behaviour.

The most valuable values to report, in order: named mutexes and pipes (they
survive re-packing better than anything else), the exact URI paths and
User-Agents used, dropped filenames, and Run-key/service/task names.

## The QEMU command line the chamber builds

You do not write this; it is here so you know what your guest will be booted
with, and which parts are load-bearing for isolation.

```
qemu-system-x86_64 -nodefaults -no-user-config -display none
  -m <memory_mb> -smp <cpus> -accel <kvm|tcg>
  -drive file=<overlay>.qcow2,format=qcow2,if=virtio,snapshot=on
  -drive file=fat:ro:<payload_dir>,format=raw,if=none,id=payload,media=disk
  -device virtio-blk-pci,drive=payload,serial=CRUCIBLE
  -chardev socket,id=crucible,path=<agent.sock>,server=on,wait=off
  -device virtio-serial-pci
  -device virtserialport,chardev=crucible,name=ffn.crucible.0
  -netdev user,id=n0,restrict=on
  -device virtio-net-pci,netdev=n0
  -object filter-dump,id=tap,netdev=n0,file=<guest.pcap>
```

The isolation-critical parts:

* **`restrict=on`** — SLIRP answers nothing and forwards nothing, so the guest
  reaches neither the host nor the internet.
* **`filter-dump`** — the chamber taps the virtual NIC and parses the capture
  for DNS questions, HTTP request lines and TLS SNI. Those are all in the first
  packet of each attempt, so they are recovered whether or not anything answered.
  This is why full isolation costs no indicators.
* **`snapshot=on` on a copy-on-write overlay** — the base image is opened
  read-only and is byte-identical after every run, so one prepared guest serves
  an unlimited number of detonations with no reprovisioning.

## Registering the guest

Write `/etc/ffn-ngfw/crucible-guests.json`:

```json
{
  "guests": [
    {
      "name": "win10-x64",
      "image": "/var/lib/ffn-ngfw/crucible/guests/win10-x64.qcow2",
      "qemu": "qemu-system-x86_64",
      "memory_mb": 4096,
      "cpus": 2,
      "accel": "kvm",
      "boot_seconds": 90,
      "extra_args": []
    }
  ]
}
```

`accel` falls back to `tcg` automatically when `/dev/kvm` is absent — correct,
but slow enough that you should expect timeouts on a real Windows guest.
`boot_seconds` is the budget for reaching the agent, on top of the per-sample
analysis timeout.

Confirm it took:

```bash
python3 ffn_crucible.py chambers
#   qemu   fidelity=2 AVAILABLE   guest win10-x64 via qemu-system-x86_64 (kvm)
```

## Building the guest, in outline

This is deliberately not a turnkey script: the licensing of a Windows guest is
yours to sort out, and the details differ per OS. The steps that matter:

1. Install the OS into a qcow2, offline.
2. Turn off everything that makes runs non-deterministic or slow: automatic
   updates, the store, telemetry, defragmentation, indexing, crash reporting,
   the screen lock, and — since you want the sample's behaviour, not a
   pre-emptive block — the bundled antivirus.
3. Auto-logon to a standard user account. Malware behaves differently as
   administrator; if you want that path, build a second guest for it rather than
   making every run privileged.
4. Install the agent and set it to run at logon.
5. Make the guest look ordinary. A pristine machine with no documents, no
   history and one CPU is detectable, and evasive samples do nothing when they
   notice. Add plausible user files, a browser history, a couple of cores, and
   more than 4 GB of disk.
6. Shut down cleanly and never boot the base image again — the chamber only ever
   opens it read-only through an overlay, and a dirty base costs you
   reproducibility.

## Things worth knowing

* **The chamber never writes to the base image.** If the base is dirty, every
  run inherits it. Keep a pristine copy.
* **A guest that never reports in is not a benign verdict.** The chamber records
  `error/no_agent` and the assay falls back to the static evidence; the report
  says `executed: false`. Check the console if you see that on every sample —
  it usually means the agent is not starting at logon.
* **`tcg` is slow.** Without KVM, a Windows guest can take minutes just to reach
  the agent. Raise `boot_seconds`, or accept that this chamber is unavailable in
  practice on a box with no virtualisation.
* **Snapshot restore, not reboot.** `snapshot=on` discards guest writes at
  shutdown, which is what makes runs independent. Nothing the sample does
  persists into the next detonation.
