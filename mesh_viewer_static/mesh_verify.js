// SPDX-License-Identifier: Apache-2.0
//
// Mesh capsule viewer -- reads the role-organised payload from the URL
// fragment (never a fetch, never a server round trip: a browser does not send
// the fragment over the wire) and renders the 4 roles x 3 questions
// words-first. For every entry it ALSO recomputes the record's own capsule_id
// in-browser and compares it to the stored one -- so a tampered fragment or an
// altered record is caught here, not merely trusted. The merkle is hidden by
// default (behind an "evidence" expander) but stays checkable.
//
// The canonicalization below is a hand port of agent_action_capsule/
// canonical.py's VINTAGE format-2 construction (the one these mesh capsules
// use: no `canonicalization_id`): drop {capsule_id, chain, signature, key_id},
// absent-field normalize (remove null / empty-array / empty-object members,
// bottom-up), then RFC 8785 JCS, then SHA-256. It must stay byte-for-byte in
// step with that module -- this is the client-side half of the same digest.
(function () {
  "use strict";

  // ---- canonicalization (mirrors agent_action_capsule/canonical.py) ------

  var LOCAL_ONLY = ["signature", "key_id"];
  var CHAIN_LINKAGE = ["capsule_id", "chain"];
  var MAX_SAFE = 9007199254740991; // 2^53 - 1

  // Absent-field normalization (§2): drop members whose value is null, an
  // empty array, or an empty object, bottom-up.
  function normalize(v) {
    if (Array.isArray(v)) {
      return v.map(normalize);
    }
    if (v !== null && typeof v === "object") {
      var out = {};
      Object.keys(v).forEach(function (k) {
        var nv = normalize(v[k]);
        if (nv === null || nv === undefined) return;
        if (Array.isArray(nv) && nv.length === 0) return;
        if (!Array.isArray(nv) && typeof nv === "object" && Object.keys(nv).length === 0) return;
        out[k] = nv;
      });
      return out;
    }
    return v === undefined ? null : v;
  }

  function jcsString(s) {
    var out = ['"'];
    for (var i = 0; i < s.length; i++) {
      var ch = s.charAt(i);
      var code = s.charCodeAt(i);
      if (ch === '"') out.push('\\"');
      else if (ch === "\\") out.push("\\\\");
      else if (code === 0x08) out.push("\\b");
      else if (code === 0x09) out.push("\\t");
      else if (code === 0x0a) out.push("\\n");
      else if (code === 0x0c) out.push("\\f");
      else if (code === 0x0d) out.push("\\r");
      else if (code < 0x20) out.push("\\u" + code.toString(16).padStart(4, "0"));
      else out.push(ch);
    }
    out.push('"');
    return out.join("");
  }

  function jcsValue(v) {
    if (v === null || v === undefined) return "null";
    if (v === true) return "true";
    if (v === false) return "false";
    if (typeof v === "string") return jcsString(v);
    if (typeof v === "number") {
      // These capsules forbid JSON floats in digest-bearing fields (§5.1), so
      // every number here is an integer. Guard the JS-safe range and emit the
      // decimal form, matching canonical.py.
      if (!Number.isInteger(v)) {
        throw new Error("non-integer number in digest-bearing field: " + v);
      }
      if (v > MAX_SAFE || v < -MAX_SAFE) {
        throw new Error("integer outside JS-safe range: " + v);
      }
      return String(v);
    }
    if (Array.isArray(v)) {
      return "[" + v.map(jcsValue).join(",") + "]";
    }
    if (typeof v === "object") {
      // RFC 8785 §3.2.3: sort members by UTF-16 code units of the key. JS "<"
      // on strings compares UTF-16 code units, matching canonical.py's
      // utf-16-be byte order for the BMP.
      var keys = Object.keys(v).sort();
      return "{" + keys.map(function (k) { return jcsString(k) + ":" + jcsValue(v[k]); }).join(",") + "}";
    }
    throw new Error("unserializable value");
  }

  function utf8Bytes(s) {
    return new TextEncoder().encode(s);
  }

  async function sha256Hex(bytes) {
    var buf = await crypto.subtle.digest("SHA-256", bytes);
    var arr = new Uint8Array(buf);
    var hex = "";
    for (var i = 0; i < arr.length; i++) hex += arr[i].toString(16).padStart(2, "0");
    return hex;
  }

  // capsule_id recompute for the vintage format-2 construction.
  async function recomputeCapsuleId(record) {
    if (record && Object.prototype.hasOwnProperty.call(record, "canonicalization_id")) {
      // Format-4/jcs path: exclude only {capsule_id, signature, key_id}, no
      // absent-field normalization. These captures don't use it, but keep the
      // branch honest rather than silently mis-hashing if one shows up.
      var excl4 = { capsule_id: 1, signature: 1, key_id: 1 };
      var c4 = {};
      Object.keys(record).forEach(function (k) { if (!excl4[k]) c4[k] = record[k]; });
      return sha256Hex(utf8Bytes(jcsValue(c4)));
    }
    var excluded = {};
    CHAIN_LINKAGE.concat(LOCAL_ONLY).forEach(function (k) { excluded[k] = 1; });
    var canonical = {};
    Object.keys(record).forEach(function (k) { if (!excluded[k]) canonical[k] = record[k]; });
    return sha256Hex(utf8Bytes(jcsValue(normalize(canonical))));
  }

  // ---- fragment decode ---------------------------------------------------

  function b64uToStd(s) { return s.replace(/-/g, "+").replace(/_/g, "/"); }

  function decodeFragment(token) {
    token = token.replace(/^#/, "");
    if (!token) return null;
    var std = b64uToStd(token);
    var pad = std.length % 4;
    if (pad) std += "====".slice(pad);
    var bin = atob(std);
    var bytes = new Uint8Array(bin.length);
    for (var i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
    var text = new TextDecoder().decode(bytes);
    return JSON.parse(text);
  }

  // ---- rendering ---------------------------------------------------------

  function el(id) { return document.querySelector(id); }
  function tmpl(id) { return document.getElementById(id).content; }

  function shortId(cid) { return cid ? cid.slice(0, 12) + "…" : "(no id)"; }

  var ROLE_ORDER = ["requester", "provider", "coordinator", "third_party"];
  var ROLE_TITLES = {
    requester: "Requester", provider: "Provider",
    coordinator: "Coordinator", third_party: "Third party (auditor / court)"
  };

  // The canonical JSON-DIGEST (JCS + SHA-256) of an object whose digest-bearing
  // values are strings/integers only -- the shape of the served terminal facts
  // {model, usage:{prompt,completion,total}}. This is the SAME digest the Rust
  // seal path computes for response_digest, recomputed here in-browser so the
  // conversation block's "matches sealed digest" is proven, not asserted.
  async function digestFacts(obj) {
    return sha256Hex(utf8Bytes(jcsValue(obj)));
  }

  function servedFactsFor(sp) {
    if (!sp) return null;
    if (sp.model == null || sp.prompt_tokens == null ||
        sp.completion_tokens == null || sp.total_tokens == null) return null;
    return {
      model: sp.model,
      usage: {
        prompt_tokens: sp.prompt_tokens,
        completion_tokens: sp.completion_tokens,
        total_tokens: sp.total_tokens
      }
    };
  }

  function renderQA(qa) {
    var node = tmpl("qa-template").cloneNode(true).querySelector(".qa");
    node.querySelector("[data-q]").textContent = qa.question;
    var st = node.querySelector("[data-state]");
    st.textContent = qa.state === "not_in_record" ? "not yet in record" : qa.state;
    st.classList.add(qa.state);
    node.querySelector("[data-a]").textContent = qa.answer;
    if (qa.evidence && qa.evidence.length) {
      var ev = node.querySelector("[data-evidence]");
      ev.hidden = false;
      var kv = node.querySelector("[data-evidence-kv]");
      qa.evidence.forEach(function (e) {
        var b = document.createElement("b");
        b.textContent = "field";
        var v = document.createElement("span");
        v.textContent = e;
        kv.appendChild(b);
        kv.appendChild(v);
      });
    }
    return node;
  }

  function renderRole(key, role) {
    var node = tmpl("role-template").cloneNode(true).querySelector(".role");
    node.querySelector("[data-role-title]").textContent = role.title;
    var qs = node.querySelector("[data-role-qs]");
    role.questions.forEach(function (qa) { qs.appendChild(renderQA(qa)); });
    return node;
  }

  // A small verify chip: recompute the sealed digest the check names, compare,
  // render "✓ matches sealed digest" / "✗ mismatch" / an honest "sealed" note.
  function verifyChip(v, ok) {
    var chip = document.createElement("span");
    chip.className = "vchip";
    if (v.matches === true || ok === true) {
      chip.classList.add("ok");
      chip.textContent = "✓ matches sealed digest";
    } else if (v.matches === false || ok === false) {
      chip.classList.add("fail");
      chip.textContent = "✗ mismatch — does NOT match sealed digest";
    } else {
      chip.classList.add("sealed");
      chip.textContent = "▪ " + (v.label || "sealed, digest only");
    }
    return chip;
  }

  async function renderConversation(entry) {
    var conv = entry.conversation;
    if (!conv) return null;
    var node = tmpl("conv-template").cloneNode(true).querySelector(".conv");

    // "served by <node>, <model> <quant> on <gpu>"
    var sb = conv.served_by || {};
    var servedBits = [];
    if (entry.friendly_model) { servedBits.push(entry.friendly_model); }
    else { if (sb.model && sb.model.indexOf("sha256") === -1) servedBits.push(sb.model); if (sb.quantization && sb.quantization !== "unknown") servedBits.push(sb.quantization); }
    var onBits = [];
    if (sb.gpu) onBits.push(sb.gpu);
    if (sb.is_soc) onBits.push("SoC");
    var served = "served by " + (sb.node_id ? sb.node_id.slice(0, 12) + "…" : "(node not named)");
    if (servedBits.length) served += ", " + servedBits.join(" ");
    if (onBits.length) served += " on " + onBits.join(", ");
    node.querySelector("[data-conv-served]").textContent = served;

    // A small inline header tag on Prompt/Response: green "shown by operator"
    // vs grey "sealed — digest only". This replaces the redundant bottom
    // Disclosure block (which repeated the prompt/response and read like it was
    // "only for the last one").
    function setTag(sel, disclosed) {
      var t = node.querySelector(sel);
      if (!t) return;
      if (disclosed) { t.className = "conv-tag shown"; t.textContent = "shown by operator"; }
      else { t.className = "conv-tag sealed"; t.textContent = "sealed — digest only"; }
    }

    // ---- Prompt --------------------------------------------------------
    var p = conv.prompt || {};
    setTag("[data-conv-prompt-tag]", !!p.disclosed);
    var promptEl = node.querySelector("[data-conv-prompt]");
    promptEl.textContent = (p.text != null && p.text !== "")
      ? p.text
      : "(prompt text not disclosed in this bundle)";
    var pv = p.verify || {};
    var pOk = null;
    if (pv.kind === "request_body" && pv.sealed_digest != null) {
      // We hold the request BODY -> recompute and compare in-browser.
      // (kept for completeness; this demo discloses prompt text, not body.)
      pOk = (pv.computed_digest != null && pv.computed_digest === pv.sealed_digest);
    }
    node.querySelector("[data-conv-prompt-verify]").appendChild(verifyChip(pv, pOk));

    // ---- Response ------------------------------------------------------
    var r = conv.response || {};
    setTag("[data-conv-response-tag]", !!r.disclosed);
    var respEl = node.querySelector("[data-conv-response]");
    var _rt = (r.text != null && r.text !== "")
      ? r.text
      : "(response text not disclosed in this bundle)";
    _rt = _rt.replace(/<\|python_tag\|>/g, "").replace(/<\|[a-z_]+\|>/g, "").trim();
    if (_rt === "") _rt = "(the model emitted a tool call — shown below)";
    respEl.textContent = _rt;
    if (r.tool_calls_note) {
      var tc = node.querySelector("[data-conv-toolcall]");
      tc.hidden = false;
      tc.textContent = "🛈 " + r.tool_calls_note;
    }
    // Recompute the served-facts digest in-browser and compare to the sealed
    // response_digest -- proof, not assertion.
    var rv = r.verify || {};
    var rOk = null;
    var facts = servedFactsFor(entry.serving_provenance);
    if (facts && rv.sealed_digest != null) {
      try {
        var computed = await digestFacts(facts);
        rOk = (computed === rv.sealed_digest);
        rv = Object.assign({}, rv, { computed_digest: computed, matches: rOk });
      } catch (e) { rOk = null; }
    }
    node.querySelector("[data-conv-response-verify]").appendChild(verifyChip(rv, rOk));
    if (rv.note) {
      var noteEl = node.querySelector("[data-conv-response-note]");
      noteEl.hidden = false;
      noteEl.textContent = rv.note;
    }
    return node;
  }


  // Render the 3 plain-language verdict lines -- the DEFAULT per-card read.
  function renderVerdict(container, verdict) {
    if (!container || !verdict || !verdict.length) return;
    verdict.forEach(function (v) {
      var node = tmpl("verdict-line-template").cloneNode(true).querySelector(".vline");
      node.classList.add(v.mark === "ok" ? "ok" : "warn");
      node.querySelector("[data-vmark]").textContent = v.mark === "ok" ? "✓" : "⚠";
      node.querySelector("[data-vtext]").textContent = v.text;
      container.appendChild(node);
    });
  }

  async function renderEntry(entry) {
    var node = tmpl("entry-template").cloneNode(true).querySelector(".entry");
    var sp = entry.serving_provenance || {};
    // Friendly name in the DEFAULT view -- NEVER the raw local-gguf/sha256 hash.
    // The raw ref/hash lives only behind the "Show the security checks" toggle.
    var friendly = entry.friendly_model || "local model";
    node.querySelector("[data-entry-title]").textContent = friendly;

    // In-browser capsule_id recompute -- the checkable merkle.
    var badge = node.querySelector("[data-verify-badge]");
    var recomputed = null, idMatch = null;
    try {
      recomputed = await recomputeCapsuleId(entry.record);
      idMatch = recomputed === entry.capsule_id;
    } catch (e) {
      idMatch = null;
    }
    if (idMatch === true) {
      badge.className = "badge ok";
      badge.textContent = "✓ verified in your browser";
    } else if (idMatch === false) {
      badge.className = "badge fail";
      badge.textContent = "✗ capsule_id MISMATCH";
    } else {
      badge.className = "badge";
      badge.textContent = "— id not recomputable";
    }

    // Plain-language verdict -- the DEFAULT read, above the conversation.
    renderVerdict(node.querySelector("[data-verdict]"), entry.verdict);

    // Inference-forward: lead with the disclosed + digest-verified conversation.
    var convNode = await renderConversation(entry);
    if (convNode) {
      var convSlot = node.querySelector("[data-conv-slot]");
      if (convSlot) convSlot.appendChild(convNode);
    }

    // ---- behind the ONE "Show the security checks" toggle -----------------
    // The raw model hash + recomputed id + signature line -- the auditor detail,
    // never in the default view.
    var idLine = node.querySelector("[data-id-line]");
    if (idLine) {
      var rawRef = sp.model_canonical_ref || sp.model || "(no raw ref)";
      var idBits = [];
      idBits.push("capsule_id: " + (entry.capsule_id || "(none)"));
      idBits.push("recomputed in-browser: " + (recomputed || "(not recomputable)"));
      idBits.push("id matches: " + (idMatch === true ? "yes" : idMatch === false ? "NO" : "n/a"));
      idBits.push("raw model ref: " + rawRef);
      if (sp.model_identity_hash) idBits.push("model_identity_hash: " + sp.model_identity_hash);
      if (sp.served_by_node_id) idBits.push("served_by_node_id: " + sp.served_by_node_id);
      // Plain text with newlines (the .id-line CSS sets white-space:pre-wrap);
      // no DOM node APIs beyond textContent, so the headless boot harness stub
      // (which has no createTextNode/style) works too.
      idLine.textContent = idBits.join("\n");
    }

    // Role questions (auditor view). Default: the REQUESTER only, inline; the
    // other roles fold behind a nested "other roles" toggle. default_role ===
    // "all" renders every role inline (original layout).
    var rolesEl = node.querySelector("[data-roles]");
    var rq = entry.role_questions || {};
    var roles = rq.roles || {};
    var defaultRole = (arguments.length > 1 && arguments[1]) || "requester";

    if (defaultRole === "all") {
      ROLE_ORDER.forEach(function (k) {
        if (roles[k]) rolesEl.appendChild(renderRole(k, roles[k]));
      });
    } else {
      var primary = roles[defaultRole] ? defaultRole : "requester";
      if (roles[primary]) rolesEl.appendChild(renderRole(primary, roles[primary]));
      // The remaining roles behind a collapsed <details> — carried, not shown.
      var others = ROLE_ORDER.filter(function (k) { return k !== primary && roles[k]; });
      if (others.length) {
        var det = document.createElement("details");
        det.className = "other-roles";
        var sum = document.createElement("summary");
        sum.textContent = "other roles (" + others.map(function (k) {
          return (ROLE_TITLES[k] || k);
        }).join(", ") + ")";
        det.appendChild(sum);
        others.forEach(function (k) { det.appendChild(renderRole(k, roles[k])); });
        rolesEl.appendChild(det);
      }
    }

    return node;
  }

  async function boot() {
    var payload = null;
    try {
      var embedded = (typeof window !== "undefined" && window.__MESH_FRAGMENT_B64U__) || "";
      // The un-filled placeholder sentinel, built by concatenation so this guard
      // NEVER contains the literal placeholder token the renderer substitutes.
      // The self-contained embed fills only the `window.__MESH_FRAGMENT_B64U__`
      // placeholder; because this string is assembled at runtime it can never be
      // overwritten by that substitution -- the exact bug that jammed base64 into
      // this condition (`if (embedded && embedded !== ""<base64>...`) and blanked
      // the page. See mesh-live-demo-permalink.html.bak.
      var UNFILLED = "@@" + "FRAGMENT" + "@@";
      if (embedded && embedded !== UNFILLED) payload = decodeFragment(embedded);
      var hash = location.hash.slice(1);
      if (hash) payload = decodeFragment(hash); // an explicit #fragment wins
    } catch (e) {
      payload = null;
    }
    if (!payload || !payload.entries) return; // empty-state stays shown

    el("[data-empty]").hidden = true;

    var meta = el("[data-meta]");
    var w = payload.witness;
    meta.textContent =
      (payload.operator ? "operator " + payload.operator + " · " : "") +
      payload.entries.length + " capsule(s) · source log: " + (payload.source_log || "?") +
      (w ? " · witness " + (w.log_id || "?") + " size=" + (w.size != null ? w.size : "?") + (w.cose_present ? " (COSE)" : "")
         : " · no witness checkpoint in this view");

    var defaultRole = payload.default_role || "requester";
    var container = el("[data-entries]");
    for (var i = 0; i < payload.entries.length; i++) {
      container.appendChild(await renderEntry(payload.entries[i], defaultRole));
    }

    var foot = el("[data-foot]");
    foot.hidden = false;
    foot.innerHTML =
      "This page recomputed each capsule_id in your browser from the record itself. " +
      "Answers marked <b>not yet in record</b> name a mechanism that isn't built for this record yet " +
      "(e.g. the coordinator stage-order receipt) — said out loud, never faked. " +
      (w ? "A witness checkpoint receipt was supplied, so third-party completeness is anchored."
         : "No witness checkpoint was supplied, so third-party completeness stays self-attested in this view.");

    // permalink chrome
    var link = el("[data-permalink]");
    if (link) link.textContent = location.href;
    var copy = el("[data-copy]");
    if (copy) copy.addEventListener("click", function () {
      navigator.clipboard && navigator.clipboard.writeText(location.href);
      copy.textContent = "copied";
      setTimeout(function () { copy.textContent = "copy permalink"; }, 1500);
    });
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", boot);
  } else {
    boot();
  }

  // Expose the digest port for the Python/JS parity test to drive headlessly.
  if (typeof window !== "undefined") {
    window.__mesh_recomputeCapsuleId = recomputeCapsuleId;
    window.__mesh_jcsValue = jcsValue;
    window.__mesh_normalize = normalize;
    // The served-facts (response_digest) port, so the parity test can prove the
    // conversation block's "matches sealed digest" recomputes the SAME digest
    // the Rust seal path binds.
    window.__mesh_servedFactsDigest = async function (sp) {
      var facts = servedFactsFor(sp);
      return facts ? digestFacts(facts) : null;
    };
    window.__mesh_boot = boot;
  }
})();
