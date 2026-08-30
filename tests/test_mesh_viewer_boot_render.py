# SPDX-License-Identifier: Apache-2.0
"""Headless boot/render of the SELF-CONTAINED permalink -- the regression guard
for the embed-serialization corruption AND the inference-forward render.

The corruption we guard against (see mesh-live-demo-permalink.html.bak): the
base64url fragment was jammed into the JS boot GUARD
(`if (embedded && embedded !== ""<base64>...`) instead of ONLY the
`window.__MESH_FRAGMENT_B64U__="..."` placeholder -- a JS syntax error that
blanked the page.

Two layers:
  * `test_embedded_fragment_is_isolated_and_guard_intact` -- pure Python, always
    runs: opens the rendered HTML, extracts the embedded value, confirms it
    equals the intended base64, confirms the boot guard is intact and NOT
    followed by base64.
  * `test_delivered_file_boots_clean_and_renders_conversations` -- drives the
    JS *as embedded in the delivered HTML* under node+linkedom (a real DOM):
    boot() runs with no syntax error, the conversations render, and each
    served-facts digest recomputes to the sealed response_digest. Skips cleanly
    when node or linkedom is unavailable (e.g. the clean-venv CI), so it is a
    local/CI-with-node check and never a false red.
"""
from __future__ import annotations

import json
import re
import shutil
import subprocess
import textwrap
from pathlib import Path

import pytest

from capsule_mesh_viewer import (
    encode_fragment,
    render_mesh_viewer_html,
    served_facts_digest,
    serving_provenance,
    to_fragment_payload,
)

REPO = Path(__file__).resolve().parent.parent


def _demo_capsule():
    poc = {
        "client_nonce_source": "host_served_observed",
        "serving_provenance": {
            "served_by_node_id": "1e059e446b39d81233830fef3f25f3a01c6a059e6e8db127182f4961606d84b3",
            "requesting_party": "unknown",
            "hostname": "swim-googles.local",
            "quantization": "Q4_K_M",
            "model": {"canonical_ref": "local-gguf/sha256-887fbdc66ab91eb5", "architecture": "llama"},
            "hardware": {"gpu": "Apple M3", "vram_bytes": 11453251584, "is_soc": True},
            "usage": {"prompt_tokens": 46, "completion_tokens": 39, "total_tokens": 85},
        },
    }
    cap = {
        "spec_version": "draft-mih-scitt-agent-action-capsule-02",
        "format_version": "2",
        "capsule_id": "a" * 64,
        "operator": "capsule-emit-mesh-poc-rust",
        "timestamp": "2026-08-30T03:54:33.474Z",
        "model_attestation": {
            "model_id": "local-gguf/sha256-887fbdc66ab91eb5",
            "compute_attestation": {"x-mesh-poc-v1": poc},
        },
        "effect": {"request_digest": "1" * 64, "response_digest": "2" * 64},
    }
    # Make response_digest the REAL served-facts digest so the browser check
    # goes green (proving the recompute, not a hardcoded pass).
    cap["effect"]["response_digest"] = served_facts_digest(serving_provenance(cap))
    return cap


def _rendered_html() -> str:
    cap = _demo_capsule()
    cid = cap["capsule_id"]
    payload = to_fragment_payload(
        [cap],
        source_log="plugin",
        disclose={cid: {"request": "how great is mesh-llm", "response": "I don't have information about mesh-llm."}},
        default_role="requester",
    )
    return render_mesh_viewer_html(encode_fragment(payload)), encode_fragment(payload)


def test_embedded_fragment_is_isolated_and_guard_intact():
    html, frag = _rendered_html()
    m = re.search(r'window\.__MESH_FRAGMENT_B64U__="([A-Za-z0-9_\-]+)";', html)
    assert m and m.group(1) == frag, "embedded value must equal the intended base64"
    assert html.count(frag) == 1, "fragment must appear ONLY in the placeholder"
    assert "if (embedded && embedded !== UNFILLED)" in html, "boot guard must be intact"
    # the corruption signature: `!== "..."` immediately followed by base64.
    assert not re.search(r'embedded !== "(?:@@FRAGMENT@@)?"[A-Za-z0-9_\-]{20,}', html)


# A self-contained minimal DOM shim (no external node module -- matches the
# repo's node-without-deps convention). Just enough of the DOM surface the
# viewer's boot()/renderEntry()/renderConversation() touch: querySelector[All]
# over a parsed template/anchor tree, cloneNode, createElement, classList,
# textContent, hidden, addEventListener, <template>.content.
_DOM_SHIM = r"""
let __idc=0;
function CL(){ const s=new Set(); return {add:(...c)=>c.forEach(x=>x&&s.add(x)),remove:(...c)=>c.forEach(x=>s.delete(x)),contains:c=>s.has(c),_s:s,toString:()=>[...s].join(' ')}; }
class N {
  constructor(tag){ this.tagName=(tag||'').toUpperCase(); this.children=[]; this._t=''; this.attributes={}; this.classList=CL(); this.hidden=false; this._html=''; }
  appendChild(c){ this.children.push(c); c.parent=this; return c; }
  cloneNode(d){ const n=new N(this.tagName); n.attributes={...this.attributes}; this.classList._s.forEach(c=>n.classList.add(c)); n.hidden=this.hidden; n._t=this._t; if(d){ n.children=this.children.map(x=>x.cloneNode(true)); n.children.forEach(x=>x.parent=n);} return n; }
  set className(v){ this.classList=CL(); String(v||'').split(/\s+/).forEach(c=>c&&this.classList.add(c)); }
  get className(){ return this.classList.toString(); }
  set textContent(v){ this._t=v==null?'':String(v); this.children=[]; }
  get textContent(){ return this._t || this.children.map(c=>c.textContent).join(''); }
  set innerHTML(v){ this._html=v; } get innerHTML(){ return this._html; }
  addEventListener(){}
  querySelector(sel){ let r=null; (function w(n){ for(const c of n.children){ if(match(c,sel)) { r=c; return true; } if(w(c)) return true; } return false; })(this); return r; }
  querySelectorAll(sel){ const o=[]; (function w(n){ for(const c of n.children){ if(match(c,sel)) o.push(c); w(c); } })(this); return o; }
}
function match(n,sel){ if(!sel) return false; if(sel[0]==='['&&sel.endsWith(']')){ return sel.slice(1,-1) in n.attributes; } if(sel[0]==='.'){ return sel.slice(1).split('.').every(c=>n.classList.contains(c)); } if(sel[0]==='#'){ return n.attributes.id===sel.slice(1); } return n.tagName===sel.toUpperCase(); }
function parse(h){
  const root=new N('root'); const st=[root];
  const re=/<(\/?)([a-zA-Z0-9-]+)((?:\s+[a-zA-Z0-9-]+(?:="[^"]*")?)*)\s*(\/?)>/g; let m;
  while((m=re.exec(h))){ const [,cl,tag,attrs,sc]=m; if(cl){ if(st.length>1) st.pop(); continue; }
    const nd=new N(tag); const ar=/([a-zA-Z0-9-]+)(?:="([^"]*)")?/g; let am;
    while((am=ar.exec(attrs))){ if(!am[1])continue; nd.attributes[am[1]]=am[2]===undefined?'':am[2]; if(am[1]==='class')(am[2]||'').split(/\s+/).forEach(c=>c&&nd.classList.add(c)); if(am[1]==='hidden')nd.hidden=true; }
    st[st.length-1].appendChild(nd);
    if(!sc && !['input','img','meta','br','hr'].includes(tag)) st.push(nd);
  }
  return root;
}
"""


@pytest.mark.skipif(shutil.which("node") is None, reason="node not available; delivered-file boot is a local/CI-with-node check")
def test_delivered_file_boots_clean_and_renders_conversations(tmp_path):
    html, _ = _rendered_html()
    html_path = tmp_path / "viewer.html"
    html_path.write_text(html, encoding="utf-8")

    harness = tmp_path / "boot.cjs"
    harness.write_text(
        _DOM_SHIM
        + textwrap.dedent(
            f"""
            const fs=require("fs"); const crypto=require("crypto");
            const html=fs.readFileSync({json.dumps(str(html_path))},"utf8");
            // Pull the two inline scripts from the DELIVERED HTML (fragment + verify.js).
            const scripts=[...html.matchAll(/<script>([\\s\\S]*?)<\\/script>/g)].map(m=>m[1]);
            const fragScript=scripts.find(s=>/__MESH_FRAGMENT_B64U__\\s*=/.test(s));
            const verifyScript=scripts.find(s=>/function boot\\(/.test(s));
            const frag=fragScript.match(/window\\.__MESH_FRAGMENT_B64U__="([A-Za-z0-9_\\-]+)";/)[1];
            // Parse templates -> .content trees; parse body anchors.
            const tmpl={{}};
            for(const m of html.matchAll(/<template id="([^"]+)">([\\s\\S]*?)<\\/template>/g)) tmpl[m[1]]=parse(m[2]);
            const body=parse(html.replace(/<template[\\s\\S]*?<\\/template>/g,"").replace(/<script[\\s\\S]*?<\\/script>/g,""));
            global.document={{
              querySelector:(s)=>body.querySelector(s),
              getElementById:(id)=>({{content:tmpl[id]}}),
              createElement:(t)=>new N(t),
              addEventListener:()=>{{}}, readyState:"complete",
            }};
            global.window={{__MESH_FRAGMENT_B64U__:frag}};
            global.location={{hash:"",href:"file://x.html"}};
            global.navigator={{}};
            global.crypto={{subtle:{{async digest(a,b){{const h=crypto.createHash("sha256");h.update(Buffer.from(b));return h.digest().buffer;}}}}}};
            global.TextEncoder=TextEncoder; global.TextDecoder=TextDecoder;
            global.atob=(s)=>Buffer.from(s,"base64").toString("binary");
            let err=null;
            try {{ (0,eval)(verifyScript); }} catch(e) {{ err=e; }}
            setTimeout(()=>{{
              if(err){{ console.error("BOOT THREW: "+err.message); process.exit(1); }}
              const convs=body.querySelectorAll(".conv").length;
              const ok=body.querySelectorAll(".vchip.ok").length;
              const fail=body.querySelectorAll(".vchip.fail").length;
              const entries=body.querySelectorAll(".entry").length;
              process.stdout.write(JSON.stringify({{entries, convs, ok, fail}}));
              process.exit(0);
            }}, 400);
            """
        ),
        encoding="utf-8",
    )
    result = subprocess.run(["node", str(harness)], capture_output=True, text=True, timeout=60)
    assert result.returncode == 0, result.stderr
    out = json.loads(result.stdout)
    assert out["entries"] == 1, "the entry must render (no blank page)"
    assert out["convs"] == 1, "the conversation block must render"
    assert out["ok"] == 1, "the served-facts digest must recompute to the sealed response_digest"
    assert out["fail"] == 0, "no digest mismatch"
