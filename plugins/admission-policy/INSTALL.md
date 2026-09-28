# capsule-emit-mesh: install on a mesh-llm node

`capsule-emit-mesh` is a mesh-llm plugin. It keeps a signed, hash-chained
record of every exchange this node serves, on this node's disk, and adds an
**Evidence** page to the console where you can see the peers you exchanged
with, each exchange, whether the other side confirmed it, and whether the log
still verifies. It installs and runs on an unmodified mesh-llm release.
Showing an exchange as confirmed by the other side needs more than the
plugin; see [Confirmed exchanges](#confirmed-exchanges-what-they-need).

## What it sends, and where it listens

Records are kept on this node. With the default settings:

| What | To whom | Default | Turn it off |
| --- | --- | --- | --- |
| This node's own sealed record of a completed exchange | the peer in that exchange | on | `share_record_at_completion = "off"` |
| Answers to record requests | past counterparties and peers about to become one | on | `share_history_segments = "off"` |
| A sealed verdict, when this node judges an exchange | the node it judged | on | `share_adjudications = "off"` |
| A signed checkpoint of the log | a witness service | **off**: only if you set `witness` | leave `witness` empty |

All peer traffic travels over mesh-llm's own peer connections; nothing goes
to any third party unless you set a witness. Each setting is under
Configuration › Plugins › Sharing policy, or in the node's config:

```toml
[[plugin]]
name = "capsule-emit-mesh"

[plugin.settings]
share_adjudications = "off"
```

Local listeners, loopback only:

- the plugin's own HTTP endpoint on `127.0.0.1` at a random port, which the
  node reaches it through;
- the evidence door (below), if you start it, on `127.0.0.1:8091` or the
  port in `ADMISSION_POLICY_EVIDENCE_SERVER_URL`.

## Install

One path, the same on macOS 11 or newer (Apple Silicon) and Linux with glibc
2.35 or newer (x86_64 or arm64; Ubuntu 22.04, Debian 12 and later). You need
`mesh-llm` itself, with plugin web UI support (`mesh-llm plugins install
--archive` must exist).

**1. Download the package for your machine and the checksum file.** Pick the
release from the
[releases page](https://github.com/action-state-group/capsule-emit-mesh/releases)
and set `VERSION` to it (without the leading `v`):

```bash
VERSION=0.2.0-rc.1
case "$(uname -s)-$(uname -m)" in
  Darwin-arm64)  TARGET=aarch64-apple-darwin ;;
  Linux-x86_64)  TARGET=x86_64-unknown-linux-gnu ;;
  Linux-aarch64) TARGET=aarch64-unknown-linux-gnu ;;
  *) echo "unsupported platform: $(uname -s)-$(uname -m)" >&2; exit 1 ;;
esac
BASE=https://github.com/action-state-group/capsule-emit-mesh/releases/download/v$VERSION
curl -fLO "$BASE/capsule-emit-mesh-$VERSION-$TARGET.tar.gz"
curl -fLO "$BASE/SHA256SUMS"
```

**2. Verify the download.** This must print `OK` for your file:

```bash
shasum -a 256 -c SHA256SUMS --ignore-missing
```

With the GitHub CLI you can also check where it was built:

```bash
gh attestation verify "capsule-emit-mesh-$VERSION-$TARGET.tar.gz" \
  --repo action-state-group/capsule-emit-mesh
```

What these prove: the checksum proves your file is byte-for-byte the one
published; the attestation proves it was built by this repository's release
workflow from the tagged commit. Neither says the code is safe to run: that
is a judgement about the source, which is public in this repository.

**3. Install it into the node's plugin directory.**

```bash
mesh-llm plugins install --archive "capsule-emit-mesh-$VERSION-$TARGET.tar.gz" \
  --name capsule-emit-mesh --version "$VERSION"
```

This unpacks the package into the node's plugin directory
(`~/.mesh-llm/plugins`, or `MESH_LLM_PLUGIN_DIR` if you set it) and marks it
enabled. `mesh-llm plugins info capsule-emit-mesh` shows what was installed.

**4. Restart the node.** An installed, enabled plugin starts with the node. No
config entry is required; the `[[plugin]]` entry above only changes settings.
The plugin keeps its records in its data directory (see
[Where the records are kept](#where-the-records-are-kept)).

**5. Open the console.** The plugin adds a page labelled **Evidence** to the
top navigation (grouped with other plugins' pages if more than one plugin adds
one). After the node serves an exchange, the page shows the peer, the
exchange, and the log's integrity. The plugin's options are under
Configuration › Plugins.

**6. Start the evidence door (needed for confirmations).** The door is the
local service the plugin hands peers' records and record requests to. It
ships in the package under `door/`. It needs `python3` 3.11 or newer; the
first run installs its pinned, hash-checked dependencies into `door/.venv`.
Start it after the node has run once, as the same user and with the same
`ADMISSION_POLICY_*` environment as the node:

```bash
~/.mesh-llm/plugins/installed/capsule-emit-mesh/door/run-door.sh
```

(If you set `MESH_LLM_PLUGIN_DIR`, the path starts there instead;
`mesh-llm plugins info capsule-emit-mesh` shows it.) It prints the data
directory it uses, which must be the plugin's (the plugin
logs its own at startup).

The door listens on loopback only and answers only the plugin: on first
start the plugin writes a random token to `<data dir>/evidence-door.token`
(readable by you alone), and every request and every reply between the two
proves that token without sending it. Another local process that takes the
door's port gets no plugin traffic it can answer. If the door is not running,
or does not prove the token, the plugin says so in its log and treats the
door as unavailable, and nothing is confirmed.

## Confirmed exchanges: what they need

**On an unmodified mesh-llm node today:**

| | |
| --- | --- |
| Install, start, the Evidence page | works |
| Each node seals its own record of an exchange | works |
| An exchange confirmed by the other side | **does not work yet** |

A confirmed exchange is a pair: the serving node's record and the requesting
node's record, matched to each other. The plugin cannot build that pair from
what mesh-llm tells it today. It needs two fields that mesh-llm does not emit
yet:

1. **`requested_by_node_id`** on the exchange event the serving node sees:
   which peer asked, taken from the connection's authenticated remote id.
   Without it the serving node does not know whom to send its record to.
2. **`served_by_node_id`, with the request and response digests,** on the
   exchange event the requesting node sees for a request another peer served.
   Without them the requesting node's record names no counterparty and has
   nothing to match.

Until both fields exist in mesh-llm, every exchange on an unmodified node
stays one-sided: each node holds only its own record, and nothing is
confirmed.

**Where the fields exist, confirmation also needs, on each node:**

- **The evidence door running** (step 6).
- **Each other node's public key.** Nodes do not exchange keys yet. The door
  accepts a record only from a peer whose key you have configured, and
  refuses the rest. Set `ADMISSION_POLICY_PEER_KEYS` in the door's
  environment to a JSON object mapping each peer's id to its raw Ed25519
  public key in hex. A node writes its own id to `<data dir>/self-peer-id`
  and its public key to `<data dir>/keys/node-key.pub.pem`.

## Where the records are kept

The plugin writes under its data directory: `ADMISSION_POLICY_DATA_DIR` if set
in the node's environment (give an absolute path), else
`$XDG_DATA_HOME/capsule-emit-mesh`, else `~/.local/share/capsule-emit-mesh`.
The sealed log is
`<data dir>/ledger/capsules.jsonl`; the door's log of what peers asked is
`<data dir>/received-log/`.

## Turn it off or remove it

```bash
mesh-llm plugins disable capsule-emit-mesh   # keeps it installed
mesh-llm plugins delete capsule-emit-mesh    # removes the installed files
```

Stop the door first if it is running. Removing the plugin does not delete its
data directory.

## Five-minute demo

[`DEMO.md`](DEMO.md): two nodes, one exchange, each side's own record, and
the Evidence page, on an unmodified mesh-llm. A confirmed exchange needs the
two fields above.

## What is in the package

```text
capsule-emit-mesh/
  capsule-emit-mesh        the plugin executable
  plugin.toml              package marker (name, version)
  plugin-manifest.json     the plugin's settings schema and web UI declaration
  bundle/register-mesh-plugin-ui.js   the Evidence page
  door/                    the evidence door: evidence_server.py, the modules
                           it imports, requirements.lock, run-door.sh
  README.md                this file
  DEMO.md                  the five-minute demo
  LICENSE, NOTICE          Apache-2.0
```

No keys or ledgers ship in the package; the node's signing key and records
are created on first start. The page's code also contains example rows for
its offline preview. It shows them only if the console is switched to its
example-data mode; in live mode, the default, it shows this node's records.

## Rebuild it yourself

Only packages built by `.github/workflows/release.yml` are published. The
workflow builds from the tagged commit with every action pinned to a commit,
a pinned Rust toolchain, `cargo build --locked` with the build machine's
paths remapped out of the executable, and `pnpm install --frozen-lockfile`.
The archive step (`plugins/admission-policy/package_release.py`) is
deterministic, so the same executable always gives the same archive digest.
To build the package for your own machine from a checkout of the tag:

```bash
cd plugins/admission-policy
RUSTFLAGS="--remap-path-prefix=$PWD=/build --remap-path-prefix=$HOME=/home" \
  cargo build --locked --release --bin admission-policy-plugin
(cd web-ui && pnpm install --frozen-lockfile && pnpm build)
python3 package_release.py --version "$VERSION" --target "$TARGET" \
  --binary target/release/admission-policy-plugin --out-dir dist
```

The resulting `dist/capsule-emit-mesh-$VERSION-$TARGET.tar.gz` installs with
the same command as step 3. A different compiler or build machine can produce
a different executable, and then a different digest; `SHA256SUMS` covers the
published packages.
