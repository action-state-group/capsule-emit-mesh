# capsule-emit-mesh: install on a mesh-llm node

`capsule-emit-mesh` is a mesh-llm plugin. It keeps a signed, hash-chained
record of every exchange this node serves, on this node's disk, and adds an
**Evidence** page to the console where you can see the peers you exchanged
with, each exchange, whether the other side confirmed it, and whether the log
still verifies. It installs and runs on an unmodified mesh-llm release.
Showing an exchange as confirmed by the other side needs more than the
plugin; see [Confirmed exchanges](#confirmed-exchanges-what-they-need).

**What leaves the machine by default.** Records are kept on this node. Only
peers you exchange with see anything: after an exchange completes, the node
sends that peer its own sealed record of that exchange, and it answers record
requests from its counterparties and from peers about to become one. Nothing
goes to any third party: a checkpoint is sent to a witness only if you set a
witness URL yourself. Each of these is a setting under Configuration ›
Plugins › Sharing policy, and each can be turned off.

## Install

One path, the same on macOS (Apple Silicon) and Linux (x86_64 or arm64). You
need `mesh-llm` itself, with plugin web UI support (`mesh-llm plugins install
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
  *) echo "no prebuilt package for this machine" >&2 ;;
esac
BASE=https://github.com/action-state-group/capsule-emit-mesh/releases/download/v$VERSION
curl -fLO "$BASE/capsule-emit-mesh-$VERSION-$TARGET.tar.gz"
curl -fLO "$BASE/SHA256SUMS"
```

**2. Verify the checksum.** This must print `OK` for your file:

```bash
shasum -a 256 -c SHA256SUMS --ignore-missing
```

**3. Install it into the node's plugin directory.**

```bash
mesh-llm plugins install --archive "capsule-emit-mesh-$VERSION-$TARGET.tar.gz" \
  --name capsule-emit-mesh --version "$VERSION"
```

This unpacks the package into the node's plugin directory
(`~/.mesh-llm/plugins`, or `MESH_LLM_PLUGIN_DIR` if you set it) and marks it
enabled. `mesh-llm plugins info capsule-emit-mesh` shows what was installed.

**4. Restart the node.** An installed, enabled plugin starts with the node. No
config entry is required. To set the plugin's options, or to turn it off, add
its entry to the node's config (the plugin id is `capsule-emit-mesh`):

```toml
[[plugin]]
name = "capsule-emit-mesh"
```

**5. Open the console.** The plugin adds a page labelled **Evidence** to the
top navigation (grouped with other plugins' pages if more than one plugin adds
one). After the node serves an exchange, the page shows the peer, the
exchange, and the log's integrity. The plugin's options are under
Configuration › Plugins.

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

**Where the fields exist, confirmation also needs two things on each node:**

- **The evidence service.** The plugin hands records it receives from peers
  to a small Python service in this repository, `evidence_server.py`, which
  checks them and answers record requests. It is not in the package. Run it
  from a checkout of this repository, with `pip install -r requirements.txt`,
  pointed at the plugin's ledger and key:

  ```bash
  python3 evidence_server.py \
    --ledger-dir <data dir>/ledger \
    --node-key <data dir>/keys/node-key.pem \
    --listen-host 127.0.0.1 --listen-port 8091
  ```

  The plugin finds it at `http://127.0.0.1:8091`, or at
  `ADMISSION_POLICY_EVIDENCE_SERVER_URL` if set in the node's environment.
- **Each other node's public key.** Nodes do not exchange keys yet. The
  evidence service accepts a record only from a peer whose key you have
  configured, and refuses the rest. Set `ADMISSION_POLICY_PEER_KEYS` in the
  service's environment to a JSON object mapping each peer's id to its raw
  Ed25519 public key in hex. A node writes its own id to
  `<data dir>/self-peer-id` and its public key to
  `<data dir>/keys/node-key.pub.pem`.

## Where the records are kept

The plugin writes under its data directory, `./admission-policy-data` relative
to the directory the node was started from; set `ADMISSION_POLICY_DATA_DIR` in
the node's environment to choose another. The sealed log is
`<data dir>/ledger/capsules.jsonl`.

## Turn it off or remove it

```bash
mesh-llm plugins disable capsule-emit-mesh   # keeps it installed
mesh-llm plugins delete capsule-emit-mesh    # removes the installed files
```

Removing the plugin does not delete its data directory.

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
  README.md                this file
  LICENSE, NOTICE          Apache-2.0
```

No keys, ledgers, or sample data ship in the package. The node's signing key
and records are created on first start.

## Rebuild it yourself

Every package is built by `.github/workflows/release.yml` from the tagged
commit, with a pinned Rust toolchain, `cargo build --locked`, and
`pnpm install --frozen-lockfile`. The archive step
(`plugins/admission-policy/package_release.py`) is deterministic, so the
same executable always gives the same archive digest. To build the package
for your own machine from a checkout of the tag:

```bash
cd plugins/admission-policy
cargo build --locked --release --bin admission-policy-plugin
(cd web-ui && pnpm install --frozen-lockfile && pnpm build)
python3 package_release.py --version "$VERSION" --target "$TARGET" \
  --binary target/release/admission-policy-plugin --out-dir dist
```

The resulting `dist/capsule-emit-mesh-$VERSION-$TARGET.tar.gz` installs with
the same command as step 3. A different compiler or build machine can produce
a different executable, and then a different digest; `SHA256SUMS` covers the
published packages.
