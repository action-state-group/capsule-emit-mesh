# capsule-emit-mesh — the 5-minute demo

Two mesh-llm nodes on one machine: node A serves a model, and node B joins A's private mesh and asks it one question. Each node runs the `capsule-emit-mesh` plugin, which keeps a signed record of every exchange the node takes part in. When both nodes hold the other's signed record of the same exchange, the plugin shows that exchange as **confirmed**.

The demo has two parts:

1. **On a stock mesh-llm node:** install the plugin from its package, see each node record the exchange, and open the plugin's Evidence page.
2. **On a mesh-llm build that has the two host fields described in the last section:** the same exchange becomes a **confirmed** row.

Nothing joins or publishes to a public mesh. Node B joins node A with an invite token kept in a private file, relays are off, and `demo.sh down` removes the token from the logs.

## What you need

| | |
|---|---|
| `MESH_LLM_BIN` | a mesh-llm release build, plus `MESH_LLM_NATIVE_RUNTIME_BUNDLE_DIR` (the native runtime built with it) |
| `PLUGIN_PKG` | the plugin package, `capsule-emit-mesh.tar.gz` for your platform |
| `python3` | 3.11 or newer, for the evidence door that ships in the package (`door/`). Its first start installs the door's pinned, hash-checked dependencies (about 60 MB) into `door/.venv` |
| `DOOR_REPO`, `PYTHON` | optional: run the door from a capsule-emit-mesh checkout instead (its `evidence_server.py`, and a Python with its `requirements.txt` installed) |
| `GGUF` | any small chat model for node A |

## Run it

`demo.sh` is in this plugin's directory in the capsule-emit-mesh repository (`plugins/admission-policy/demo.sh`); run it from a checkout.

```bash
export MESH_LLM_BIN=... MESH_LLM_NATIVE_RUNTIME_BUNDLE_DIR=... PLUGIN_PKG=... GGUF=...
./demo.sh up        # about 2 minutes, most of it loading the model
./demo.sh ask       # optional: one more exchange
./demo.sh status
./demo.sh down
```

## What you see, step by step

**1. Install the plugin — one command per node.**

```bash
mesh-llm plugins install --archive capsule-emit-mesh.tar.gz --name capsule-emit-mesh
```

`mesh-llm plugins list` then shows `capsule-emit-mesh … state=enabled`. No config entry is needed: the node starts installed, enabled plugins by itself. A `[[plugin]] name = "capsule-emit-mesh"` entry is only needed if you want to change the plugin's settings.

Use `plugins install`; don't unpack the archive into the plugin directory by hand. The install writes the metadata the node reads to find the plugin.

**2. Start the two nodes.**

- Node A: `mesh-llm serve --gguf …`.
- Node B: `mesh-llm client --join-file …`. It joins A's private mesh and lists A's model.
- Consoles: node A at `http://127.0.0.1:3811`, node B at `http://127.0.0.1:3812`.

**3. Each node's evidence door starts, knowing the other node's public key.**

- When the plugin starts, it writes the node's id and public key, and a random token in its data directory (`evidence-door.token`).
- Each node starts the evidence door that ships in the package: `door/run-door.sh` in the installed plugin directory, with the node's `ADMISSION_POLICY_DATA_DIR` and `ADMISSION_POLICY_EVIDENCE_SERVER_URL`. It is started knowing the other node's key (`ADMISSION_POLICY_PEER_KEYS`), before any traffic, and checks the signature of every record it receives against that key.
- The door listens on loopback only and answers only its own plugin: every request and reply between them proves the token. If the door isn't running, the plugin's Evidence page says confirmation is unavailable.

**4. One exchange: node B asks node A's model.**

- Node A's plugin seals a `served` record of the exchange: request digest, response digest, model, weights digest, and the node that served it.
- Node B's plugin seals a `requested` record.

**5. Open the plugin's page.**

- Go to `http://127.0.0.1:3812/plugins/capsule-emit-mesh/evidence`. You can also reach it from the console's plugin navigation.
- The page shows this node's copy of its records, then **Peers**, **Exchanges** and **Integrity**.

## On a stock node today

Steps 1, 2, 4 and 5 work on a stock mesh-llm node:
- the install;
- the page (served by the node from the plugin's package);
- a signed record on each side.

The exchange does **not** become confirmed on a stock node. The two records can't be matched to each other, because the node doesn't give the plugin two facts:

| Side | What the plugin needs from the node | Why |
|---|---|---|
| The node that **served** the request | the id of the node that **asked** (`requested_by_node_id`), taken from the mesh connection the request arrived on | to know whom to send its signed record to |
| The node that **asked** | the id of the node that **served** it, and the request and response digests, on the completed-exchange event for a request it sent over the mesh | to seal a complete record, and to match the other node's record to its own |

These two fields are the whole ask of the host.

## With the two host fields: the confirmed row

On a mesh-llm build that provides both fields, the same `./demo.sh up` ends with:

```
node a: 1 exchange records of its own · 1 records received from the other node · 1 confirmed by the other node
node b: 1 exchange records of its own · 1 records received from the other node · 1 confirmed by the other node
```

In **Exchanges**, the row shows **confirmed**: the other node's record verified against its key, and both records carry the same request and response digests.

A record whose digests disagree shows as **contradicted**. A record that fails its signature check, or comes from a node whose key isn't known, is **refused** and never shown as confirmed.

## A paid exchange

On a mesh-llm build with paid inference and a test wallet (no real funds), node A sets a price and node B pays for its answers automatically:

```bash
mesh-llm wallet --port 3811 pricing <model> --input-msat-per-million 1000000 --output-msat-per-million 3000000   # node A
mesh-llm wallet --port 3812 policy --mode automatic --daily-budget-sats 100                                       # node B
mesh-llm wallet --port 3812 get-balance                                                                            # node B: opens its wallet
```

**Open node B's wallet before the first paid question**, with `wallet get-balance` as above. Setting the policy doesn't open the wallet, and until it's open node B counts no spendable budget. So it leaves out every paid provider and answers HTTP 402 "paid providers are unavailable under the current payment policy, local payee blocklist, wallet balance or daily budget". Once the wallet is open, the next request is paid. (Right after node A sets its price you may also briefly see 402 "this provider requires the Lightning payment protocol". Ask again.)

Node B then records each step of the payment: the terms it accepted, each invoice node A stated, each payment its own wallet reported, and the final amount. This works for streamed Chat turns and non-streamed requests alike. On node B's Evidence page the exchange reads **paid · settled**. It says "settled" only because node B's wallet reported the payment, never on the other node's word. An exchange with no payment records never reads "unpaid".
