"use strict";

// Every value that reaches the DOM here originates upstream: finding
// titles, descriptions and diffs come from scanned repositories and LLM
// output, so they are untrusted attacker-influenced text. The whole UI is
// therefore built with createElement + textContent. Nothing is ever
// assigned as markup, and the document's CSP forbids inline script so an
// escaping slip cannot execute anyway.

let CONFIG = {
  poll_seconds: 5,
  protocol_version: null,
  request_header: "X-Loupe-Dashboard",
  capability_header: "X-Loupe-Capability",
};
let CAPABILITY_TOKEN = null;
let REPOS = [];
// The server-wide GitHub App ({ app_id, slug }) or null while none is
// configured. Decides whether the PAT field is optional and which GitHub
// actions a repo row offers.
let GITHUB_APP = null;
let FINDINGS = [];
let CURRENT_VIEW = "repos";
let POLL_TIMER = null;
let POLL_GENERATION = 0;
let JOBS_LOAD = null;
let JOBS_RELOAD_REQUESTED = false;

// ----------------------------------------------------------------- helpers

function el(tag, opts, children) {
  const node = document.createElement(tag);
  if (opts) {
    if (opts.text !== undefined) node.textContent = String(opts.text);
    if (opts.class) node.className = opts.class;
    if (opts.title) node.title = opts.title;
    if (opts.attrs) {
      for (const [k, v] of Object.entries(opts.attrs)) node.setAttribute(k, v);
    }
    if (opts.on) {
      for (const [event, fn] of Object.entries(opts.on)) node.addEventListener(event, fn);
    }
  }
  for (const child of children || []) {
    if (child === null || child === undefined || child === false) continue;
    node.appendChild(typeof child === "string" ? document.createTextNode(child) : child);
  }
  return node;
}

function clear(node) {
  while (node.firstChild) node.removeChild(node.firstChild);
}

function $(id) {
  return document.getElementById(id);
}

function banner(message) {
  const node = $("banner");
  if (!message) {
    node.hidden = true;
    node.textContent = "";
    return;
  }
  node.textContent = message;
  node.hidden = false;
}

/** Epoch seconds -> local time plus a coarse relative hint. */
function when(seconds) {
  if (seconds === null || seconds === undefined) return "—";
  const date = new Date(seconds * 1000);
  return date.toLocaleString();
}

function duration(seconds) {
  if (seconds === null || seconds === undefined) return "—";
  const s = Math.max(0, Math.round(seconds));
  if (s < 60) return s + "s";
  if (s < 3600) return Math.floor(s / 60) + "m " + (s % 60) + "s";
  return Math.floor(s / 3600) + "h " + Math.floor((s % 3600) / 60) + "m";
}

function nowSeconds() {
  return Math.floor(Date.now() / 1000);
}

// -------------------------------------------------------------------- fetch

function bootstrapCapability() {
  const fragment = new URLSearchParams(window.location.hash.slice(1));
  const fromFragment = fragment.get("t");
  if (fromFragment !== null) {
    window.sessionStorage.setItem("loupe_dashboard_capability", fromFragment);
    window.history.replaceState(null, "", window.location.pathname + window.location.search);
  }
  CAPABILITY_TOKEN = window.sessionStorage.getItem("loupe_dashboard_capability");
}

async function api(method, path, body) {
  const headers = {};
  const options = { method, headers, credentials: "omit" };
  if (CAPABILITY_TOKEN !== null) {
    headers[CONFIG.capability_header] = CAPABILITY_TOKEN;
  }
  if (method !== "GET" && method !== "HEAD") {
    // Required by the server-side guard: a cross-origin caller cannot set
    // a custom header without a preflight we refuse, which is what stops
    // a page the operator visits from driving this dashboard.
    headers[CONFIG.request_header] = "1";
  }
  if (body !== undefined) {
    headers["Content-Type"] = "application/json";
    options.body = JSON.stringify(body);
  }
  const resp = await fetch(path, options);
  if (resp.status === 204) return null;

  const text = await resp.text();
  let parsed = null;
  if (text.length > 0) {
    try {
      parsed = JSON.parse(text);
    } catch (e) {
      parsed = null;
    }
  }
  if (!resp.ok) {
    const detail = parsed && parsed.error ? parsed.error : text || resp.statusText;
    throw new Error(detail);
  }
  return parsed;
}

/** Run an action, surfacing failures in the banner instead of silently. */
async function guarded(fn) {
  try {
    banner("");
    await fn();
  } catch (e) {
    banner(String(e.message || e));
  }
}

// -------------------------------------------------------------------- status

async function refreshStatus() {
  try {
    const who = await api("GET", "/api/whoami");
    $("identity").textContent = who.name + " (" + who.kind + ")";
  } catch (e) {
    $("identity").textContent = "unknown identity";
  }
  const pill = $("health");
  try {
    const health = await api("GET", "/api/health");
    pill.textContent = "server " + health.status + " · protocol " + health.protocol_version;
    pill.className = "pill ok";
    if (CONFIG.protocol_version !== null && health.protocol_version !== CONFIG.protocol_version) {
      banner(
        "Protocol mismatch: loupe-server speaks " +
          health.protocol_version +
          ", this loupe-web build speaks " +
          CONFIG.protocol_version +
          ". Rebuild loupe-web against the running server — requests will fail until you do."
      );
    }
  } catch (e) {
    pill.textContent = "server unreachable";
    pill.className = "pill bad";
    banner(String(e.message || e));
  }
}

// --------------------------------------------------------------------- repos

function reportingLabel(reporting) {
  if (!reporting) return "unknown";
  if (reporting.kind === "github_issue") {
    const via = reporting.auth === "app" ? " (via app)" : reporting.auth === "pat" ? " (via PAT)" : "";
    return "github issues → " + reporting.target_owner + "/" + reporting.target_repo + via;
  }
  if (reporting.kind === "email") return "email → " + (reporting.to || []).join(", ");
  if (reporting.kind === "manual") return "manual (no reporter)";
  return reporting.kind;
}

function approvalLabel(repo) {
  if (repo.require_approval === true) return "approval: required (pinned)";
  if (repo.require_approval === false) return "approval: off (pinned)";
  return "approval: server default";
}

/** Re-point a repo at a GitHub tracker. Without `pat` the server switches
 *  the repo to the GitHub App, so the key is left out rather than sent
 *  empty. */
async function setGithubReporting(repo, owner, target, pat) {
  const payload = { target_owner: owner, target_repo: target };
  if (pat) payload.github_pat = pat;
  await api("PUT", "/api/repos/" + repo.id + "/reporting/github", payload);
  await loadRepos();
}

/** The GitHub-related actions for a repo row, which depend on how the
 *  repo currently authenticates: PAT-backed repos can rotate the PAT or
 *  move to the app, app-backed repos can fall back to a PAT, and anything
 *  else can be pointed at a tracker. */
function githubActions(repo) {
  const reporting = repo.reporting || {};
  if (reporting.kind !== "github_issue") {
    return [
      el("button", {
        text: "Set GitHub reporting…",
        class: "secondary",
        title: "Point this repo at a GitHub tracker; works from any current destination",
        on: { click: () => guarded(async () => {
          const owner = window.prompt("Target owner:");
          if (owner === null || owner.trim() === "") return;
          const target = window.prompt("Target repo:");
          if (target === null || target.trim() === "") return;
          const pat = window.prompt("GitHub PAT (leave empty to use the GitHub App):");
          if (pat === null) return;
          await setGithubReporting(repo, owner.trim(), target.trim(), pat.trim());
        }) },
      }),
    ];
  }
  if (reporting.auth === "app") {
    return [
      el("button", {
        text: "Use a PAT instead…",
        class: "secondary",
        title: "File issues with a personal access token rather than the GitHub App",
        on: { click: () => guarded(async () => {
          const pat = window.prompt("GitHub PAT (not echoed back anywhere):");
          if (pat === null || pat.trim() === "") return;
          await setGithubReporting(repo, reporting.target_owner, reporting.target_repo, pat.trim());
        }) },
      }),
    ];
  }
  const switchOpts = {
    text: "Switch to GitHub App",
    class: "secondary",
    title: GITHUB_APP
      ? "Drop this repo's PAT and file issues through the GitHub App " + GITHUB_APP.slug
      : "No GitHub App is configured on this server; set one with loupectl github-app set",
    on: { click: () => guarded(async () => {
      // The button's disabled state was fixed when the row rendered; the
      // app may have been cleared since, so re-check before using it.
      if (!GITHUB_APP) {
        throw new Error("No GitHub App is configured on this server; set one with loupectl github-app set");
      }
      if (!window.confirm(
        "Switch repo #" + repo.id + " to the GitHub App?\n\n" +
        "Its stored PAT is dropped; issues on " + reporting.target_owner + "/" +
        reporting.target_repo + " will be filed by " + GITHUB_APP.slug + "[bot]."
      )) return;
      await setGithubReporting(repo, reporting.target_owner, reporting.target_repo, "");
    }) },
  };
  if (!GITHUB_APP) switchOpts.attrs = { disabled: "" };
  return [
    el("button", {
      text: "Update PAT…",
      class: "secondary",
      on: { click: () => guarded(async () => {
        const pat = window.prompt("New GitHub PAT (not echoed back anywhere):");
        if (pat === null || pat.trim() === "") return;
        await api("POST", "/api/repos/" + repo.id + "/reporting/github-pat", {
          github_pat: pat.trim(),
        });
        banner("");
        window.alert("PAT rotated for repo #" + repo.id + ".");
      }) },
    }),
    el("button", switchOpts),
  ];
}

function repoRow(repo) {
  const disabled = repo.disabled_at !== null && repo.disabled_at !== undefined;

  const meta = el("div", { class: "row-meta" }, [
    el("span", { text: "#" + repo.id }),
    el("span", { text: reportingLabel(repo.reporting) }),
    el("span", {
      text: repo.scan_interval_seconds ? "every " + duration(repo.scan_interval_seconds) : "manual scans",
    }),
    el("span", { text: repo.verification_enabled ? "verify: on" : "verify: off" }),
    el("span", { text: approvalLabel(repo) }),
    el("span", {
      text: "last scan: " + when(repo.last_scanned_at),
      title: repo.last_scanned_sha ? "at " + repo.last_scanned_sha : "never scanned",
    }),
  ]);

  const actions = el("div", { class: "row-actions" }, [
    el("button", {
      text: "Scan",
      on: { click: () => guarded(async () => {
        await api("POST", "/api/repos/" + repo.id + "/scan", { incremental: false });
        banner("");
        switchView("jobs");
      }) },
    }),
    el("button", {
      text: "Scan (incremental)",
      class: "secondary",
      title: "Scan only what changed since the last scanned commit",
      on: { click: () => guarded(async () => {
        await api("POST", "/api/repos/" + repo.id + "/scan", { incremental: true });
        switchView("jobs");
      }) },
    }),
    el("button", {
      text: disabled ? "Enable" : "Disable",
      class: "secondary",
      title: disabled ? "Resume scheduled scans" : "Pause scheduled scans",
      on: { click: () => guarded(async () => {
        await api("PATCH", "/api/repos/" + repo.id, { disabled: !disabled });
        await loadRepos();
      }) },
    }),
    el("button", {
      text: "Interval…",
      class: "secondary",
      on: { click: () => guarded(async () => {
        const raw = window.prompt(
          "Scan interval in seconds (empty to leave unchanged):",
          repo.scan_interval_seconds || ""
        );
        if (raw === null || raw.trim() === "") return;
        const parsed = Number(raw);
        if (!Number.isInteger(parsed) || parsed < 1) throw new Error("interval must be a positive integer");
        await api("PATCH", "/api/repos/" + repo.id, { scan_interval_seconds: parsed });
        await loadRepos();
      }) },
    }),
    el("button", {
      text: repo.verification_enabled ? "Verify: off" : "Verify: on",
      class: "secondary",
      on: { click: () => guarded(async () => {
        await api("PATCH", "/api/repos/" + repo.id, {
          verification_enabled: !repo.verification_enabled,
        });
        await loadRepos();
      }) },
    }),
    el("button", {
      text: "Approval…",
      class: "secondary",
      title: "Require approval, skip it, or inherit the server default",
      on: { click: () => guarded(async () => {
        const choice = window.prompt(
          "Approval gate: type 'on', 'off', or 'inherit' to fall back to the server default:",
          repo.require_approval === null || repo.require_approval === undefined
            ? "inherit"
            : repo.require_approval ? "on" : "off"
        );
        if (choice === null) return;
        const normalized = choice.trim().toLowerCase();
        let payload;
        if (normalized === "on") payload = { require_approval: true };
        else if (normalized === "off") payload = { require_approval: false };
        else if (normalized === "inherit") payload = { inherit_require_approval: true };
        else throw new Error("expected on, off, or inherit");
        await api("PATCH", "/api/repos/" + repo.id, payload);
        await loadRepos();
      }) },
    }),
    ...githubActions(repo),
    el("button", {
      text: "Findings",
      class: "secondary",
      on: { click: () => { $("findings-repo").value = String(repo.id); switchView("findings"); } },
    }),
    el("button", {
      text: "Delete",
      class: "danger",
      on: { click: () => guarded(async () => {
        if (!window.confirm(
          "Delete repo #" + repo.id + " (" + repo.owner + "/" + repo.repo + ")?\n\n" +
          "This cascades to its jobs, findings and scan history."
        )) return;
        await api("DELETE", "/api/repos/" + repo.id);
        await loadRepos();
      }) },
    }),
  ]);

  return el("div", { class: "row" }, [
    el("div", { class: "row-head" }, [
      el("span", { class: "row-title", text: repo.owner + "/" + repo.repo }),
      disabled ? el("span", { class: "tag state-cancelled", text: "disabled" }) : null,
      el("span", { class: "row-meta mono", text: repo.clone_url }),
    ]),
    meta,
    actions,
  ]);
}

async function loadRepos() {
  const repos = await api("GET", "/api/repos");
  REPOS = repos.repos || [];
  const list = $("repos-list");
  clear(list);
  if (REPOS.length === 0) {
    list.appendChild(el("p", { class: "empty", text: "No repositories registered yet." }));
  } else {
    for (const repo of REPOS) list.appendChild(repoRow(repo));
  }
  syncRepoSelect();
}

/** Refresh the GitHub App status. A failure must not take the whole repos view down:
 *  fall back to "no app" and report the error, but let the caller carry
 *  on loading repos. */
async function loadGithubApp() {
  try {
    const status = await api("GET", "/api/github-app");
    GITHUB_APP = status.app || null;
  } catch (e) {
    GITHUB_APP = null;
    banner("GitHub App status unavailable: " + String(e.message || e));
  }
  applyGithubAuthHint();
}

/** Explain what an empty PAT field does, and only insist on one when the
 *  server has no app to fall back to. `required` is set only while the
 *  GitHub block is the visible one: a required control inside a hidden
 *  block would block submitting an email or manual registration. */
function applyGithubAuthHint() {
  const hint = $("github-auth-hint");
  const pat = document.querySelector("#repo-add input[name=github_pat]");
  const githubSelected = document.querySelector("#repo-add input[name=reporting]:checked");
  const githubVisible = githubSelected !== null && githubSelected.value === "github_issue";
  if (GITHUB_APP) {
    hint.textContent =
      "Leave empty to report through the GitHub App " + GITHUB_APP.slug +
      " (App ID " + GITHUB_APP.app_id + "). Fill in only to file issues with a personal token instead.";
    pat.required = false;
  } else {
    hint.textContent =
      "No GitHub App is configured on this server, so a PAT is required until one is set with " +
      "`loupectl github-app set`.";
    pat.required = githubVisible;
  }
}

function syncRepoSelect() {
  const select = $("findings-repo");
  const previous = select.value;
  clear(select);
  for (const repo of REPOS) {
    select.appendChild(
      el("option", { text: repo.owner + "/" + repo.repo + " (#" + repo.id + ")", attrs: { value: String(repo.id) } })
    );
  }
  if (previous && REPOS.some((r) => String(r.id) === previous)) select.value = previous;
}

function readRepoForm(form) {
  const data = new FormData(form);
  const text = (name) => {
    const value = data.get(name);
    return value === null ? "" : String(value).trim();
  };

  const payload = { clone_url: text("clone_url") };
  if (text("branch")) payload.branch = text("branch");
  if (text("scan_interval_seconds")) {
    payload.scan_interval_seconds = Number(text("scan_interval_seconds"));
  }
  if (data.get("verification_enabled")) payload.verification_enabled = true;
  if (data.get("require_approval")) payload.require_approval = true;

  const kind = text("reporting");
  if (kind === "github_issue") {
    payload.reporting = {
      kind: "github_issue",
      target_owner: text("target_owner"),
      target_repo: text("target_repo"),
    };
    if (!payload.reporting.target_owner || !payload.reporting.target_repo) {
      throw new Error("GitHub reporting needs a target owner and repo");
    }
    // An absent `github_pat` means "report through the GitHub App"; an
    // empty string would be rejected as an empty PAT, so never send one.
    if (text("github_pat")) payload.reporting.github_pat = text("github_pat");
    else if (!GITHUB_APP) throw new Error("GitHub reporting needs a PAT (no GitHub App is configured)");
  } else if (kind === "email") {
    const to = text("email_to").split(",").map((s) => s.trim()).filter((s) => s.length > 0);
    if (to.length === 0) throw new Error("email reporting needs at least one recipient");
    payload.reporting = { kind: "email", to };
    if (text("email_from")) payload.reporting.from = text("email_from");
    if (text("email_subject_prefix")) payload.reporting.subject_prefix = text("email_subject_prefix");
  } else {
    payload.reporting = { kind: "manual" };
  }
  return payload;
}

// ---------------------------------------------------------------------- jobs

const FINISHED_STATES = "succeeded,failed,cancelled";

function jobRow(job) {
  const meta = [
    el("span", { text: "repo #" + job.repo_id }),
    el("span", { text: job.kind + (job.incremental ? " (incremental)" : "") }),
    el("span", { text: "queued " + when(job.enqueued_at) }),
  ];
  if (job.worker_id !== null && job.worker_id !== undefined) {
    meta.push(el("span", { text: "worker #" + job.worker_id }));
  }
  if (job.attempts > 0) {
    meta.push(el("span", { text: "attempt " + job.attempts + "/3", title: "MAX_ATTEMPTS is 3" }));
  }
  if (job.state === "leased" && job.lease_expires_at) {
    const remaining = job.lease_expires_at - nowSeconds();
    meta.push(
      el("span", {
        text: remaining > 0 ? "lease expires in " + duration(remaining) : "lease expired — awaiting reaper",
        title: "A lapsed lease is requeued by the server's reaper",
      })
    );
  }
  if (job.started_at && job.finished_at) {
    meta.push(el("span", { text: "ran " + duration(job.finished_at - job.started_at) }));
  }
  if (job.target_finding_id) {
    meta.push(el("span", { text: "finding #" + job.target_finding_id }));
  }

  const children = [
    el("div", { class: "row-head" }, [
      el("span", { class: "row-title", text: "job #" + job.job_id }),
      el("span", { class: "tag state-" + job.state, text: job.state }),
    ]),
    el("div", { class: "row-meta" }, meta),
  ];

  if (job.error) {
    children.push(el("div", { class: "row-meta mono", text: job.error }));
  }

  // Only offer transitions the server's state machine actually permits:
  // retry is legal from failed, cancel from queued or leased. Offering
  // either elsewhere would just earn a 409.
  const actions = [];
  if (job.state === "failed") {
    actions.push(
      el("button", {
        text: "Retry",
        class: "secondary",
        on: { click: () => guarded(async () => {
          await api("POST", "/api/jobs/" + job.job_id + "/retry");
          await loadJobs();
        }) },
      })
    );
  }
  if (job.state === "queued" || job.state === "leased") {
    actions.push(
      el("button", {
        text: "Cancel",
        class: "danger",
        on: { click: () => guarded(async () => {
          await api("POST", "/api/jobs/" + job.job_id + "/cancel");
          await loadJobs();
        }) },
      })
    );
  }
  if (actions.length > 0) children.push(el("div", { class: "row-actions" }, actions));

  return el("div", { class: "row" }, children);
}

function renderJobColumn(containerId, countId, jobs) {
  const container = $(containerId);
  clear(container);
  $(countId).textContent = String(jobs.length);
  if (jobs.length === 0) {
    container.appendChild(el("p", { class: "empty", text: "Nothing here." }));
    return;
  }
  for (const job of jobs) container.appendChild(jobRow(job));
}

async function loadJobsNow() {
  const limit = Number($("jobs-limit").value) || 25;
  const kind = $("jobs-kind").value;
  const query = (states) => {
    const params = new URLSearchParams({ state: states, limit: String(limit) });
    if (kind) params.set("kind", kind);
    return "/api/jobs?" + params.toString();
  };

  // One set-valued state filter covers the whole "finished" group, reducing
  // contention on the server's shared database connection.
  const [queued, leased, finished] = await Promise.all([
    api("GET", query("queued")),
    api("GET", query("leased")),
    api("GET", query(FINISHED_STATES)),
  ]);

  renderJobColumn("jobs-queued", "count-queued", queued || []);
  renderJobColumn("jobs-leased", "count-leased", leased || []);
  renderJobColumn("jobs-finished", "count-finished", finished || []);
  $("jobs-scope").textContent =
    "Showing up to " + limit + " most recent per column. Counts are for what is shown, not totals.";
}

/** Coalesce concurrent refresh requests into at most one follow-up load.
 *  A refresh fans out to three server requests, so allowing two refreshes
 *  to overlap would multiply contention on the server's database. */
function loadJobs() {
  JOBS_RELOAD_REQUESTED = true;
  if (JOBS_LOAD === null) {
    JOBS_LOAD = (async () => {
      try {
        while (JOBS_RELOAD_REQUESTED) {
          JOBS_RELOAD_REQUESTED = false;
          await loadJobsNow();
        }
      } finally {
        JOBS_LOAD = null;
      }
    })();
  }
  return JOBS_LOAD;
}

// ------------------------------------------------------------------ findings

/** Mirrors loupe_storage::findings::sanitize_fts_query so we can explain
 *  an empty result instead of showing a misleading "no matches". */
function usableSearchTerms(input) {
  return input
    .split(/\s+/)
    .map((token) => token.replace(/["*:()']/g, "").trim())
    .filter((token) => token.length >= 2);
}

function findingRow(finding) {
  return el("div", {
    class: "row clickable",
    on: { click: () => guarded(() => showFinding(finding.id)) },
  }, [
    el("div", { class: "row-head" }, [
      el("span", { class: "tag sev-" + finding.severity, text: finding.severity }),
      el("span", { class: "row-title", text: finding.title }),
      el("span", { class: "tag state-" + finding.state, text: finding.state.replace(/_/g, " ") }),
    ]),
    el("div", { class: "row-meta" }, [
      el("span", { text: "#" + finding.id }),
      el("span", { text: finding.scanner_id }),
      finding.file_path
        ? el("span", {
            class: "mono",
            text: finding.file_path + (finding.line_start ? ":" + finding.line_start : ""),
          })
        : null,
      el("span", { text: when(finding.created_at) }),
      finding.verification_required ? el("span", { text: "verify required" }) : null,
    ]),
  ]);
}

/** Render a unified diff one node per line, so nothing is interpreted. */
function diffBlock(unified) {
  const box = el("div", { class: "diff mono" }, []);
  for (const line of unified.split("\n")) {
    let cls = "";
    if (line.startsWith("+++") || line.startsWith("---")) cls = "hunk";
    else if (line.startsWith("@@")) cls = "hunk";
    else if (line.startsWith("+")) cls = "add";
    else if (line.startsWith("-")) cls = "del";
    box.appendChild(el("div", { class: cls, text: line }));
  }
  return box;
}

function approvalExplanation(finding) {
  const repo = REPOS.find((r) => r.id === finding.repo_id);
  if (repo && repo.require_approval === true) {
    return "Parked because this repository pins require_approval = true.";
  }
  if (repo && (repo.require_approval === null || repo.require_approval === undefined)) {
    return "Parked because the server's require_approval default is on for this repository.";
  }
  return "Parked awaiting approval.";
}

async function showFinding(id) {
  const finding = await api("GET", "/api/findings/" + id);
  const box = $("finding-detail");
  clear(box);

  const kv = el("dl", { class: "kv" }, []);
  const pair = (key, value) => {
    kv.appendChild(el("dt", { text: key }));
    kv.appendChild(el("dd", { text: value }));
  };
  pair("id", "#" + finding.id);
  pair("repo", "#" + finding.repo_id);
  pair("job", "#" + finding.job_id);
  pair("scanner", finding.scanner_id);
  pair("severity", finding.severity);
  pair("state", finding.state.replace(/_/g, " "));
  if (finding.cwe) pair("cwe", finding.cwe);
  if (finding.file_path) {
    const span = finding.line_end && finding.line_end !== finding.line_start
      ? finding.line_start + "–" + finding.line_end
      : finding.line_start;
    pair("location", finding.file_path + (span ? ":" + span : ""));
  }
  pair("fingerprint", finding.fingerprint);
  pair("created", when(finding.created_at));
  if (finding.approved_at) pair("approved", when(finding.approved_at) + " by " + (finding.approved_by_cn || "?"));
  if (finding.rejected_at) pair("rejected", when(finding.rejected_at) + " by " + (finding.rejected_by_cn || "?"));

  const children = [
    el("div", { class: "row-head" }, [
      el("span", { class: "tag sev-" + finding.severity, text: finding.severity }),
      el("h3", { text: finding.title }),
    ]),
    kv,
  ];

  if (finding.state === "awaiting_approval") {
    children.push(el("p", { class: "hint", text: approvalExplanation(finding) }));
  }

  children.push(el("h3", { text: "Description" }));
  children.push(el("p", { class: "desc", text: finding.description }));

  if (finding.poc_unified) {
    children.push(el("h3", { text: "Proof of concept" }));
    children.push(el("p", {
      class: "hint",
      text: "A regression test that should fail on HEAD. This is the strongest evidence the finding is real.",
    }));
    children.push(diffBlock(finding.poc_unified));
  }
  if (finding.patch_unified) {
    children.push(el("h3", { text: "Proposed patch" }));
    children.push(diffBlock(finding.patch_unified));
  }

  const actions = [];
  if (finding.state === "awaiting_approval") {
    actions.push(el("button", {
      text: "Approve",
      on: { click: () => guarded(async () => {
        await api("POST", "/api/findings/" + finding.id + "/approve");
        await loadFindings();
        await showFinding(finding.id);
      }) },
    }));
    actions.push(el("button", {
      text: "Reject",
      class: "danger",
      title: "Terminal: the finding is dismissed and recorded against your admin identity",
      on: { click: () => guarded(async () => {
        if (!window.confirm("Reject finding #" + finding.id + "? This is terminal.")) return;
        await api("POST", "/api/findings/" + finding.id + "/reject");
        await loadFindings();
        await showFinding(finding.id);
      }) },
    }));
  }
  if (finding.state === "confirmed") {
    actions.push(el("button", {
      text: "Retry report",
      class: "secondary",
      on: { click: () => guarded(async () => {
        await api("POST", "/api/findings/" + finding.id + "/retry-report");
        await loadFindings();
        await showFinding(finding.id);
      }) },
    }));
  }
  actions.push(el("button", {
    text: "Close",
    class: "secondary",
    on: { click: () => { box.hidden = true; clear(box); } },
  }));
  children.push(el("div", { class: "row-actions" }, actions));

  for (const child of children) box.appendChild(child);
  box.hidden = false;
  box.scrollIntoView({ block: "nearest" });
}

function applyFindingFilters() {
  const state = $("findings-state").value;
  const severity = $("findings-severity").value;
  const filtered = FINDINGS.filter(
    (f) => (!state || f.state === state) && (!severity || f.severity === severity)
  );

  const list = $("findings-list");
  clear(list);
  if (filtered.length === 0) {
    list.appendChild(el("p", { class: "empty", text: "No findings match." }));
  } else {
    for (const finding of filtered) list.appendChild(findingRow(finding));
  }
  return filtered.length;
}

async function loadFindings() {
  const repoId = $("findings-repo").value;
  if (!repoId) {
    clear($("findings-list"));
    $("findings-scope").textContent = "Register a repository first.";
    return;
  }
  const limit = Number($("findings-limit").value) || 200;
  const body = await api("GET", "/api/repos/" + repoId + "/findings?limit=" + limit);
  FINDINGS = body.findings || [];
  const shown = applyFindingFilters();
  // State and severity filtering is client-side because the server has no
  // filter for them, so say what the numbers actually cover.
  $("findings-scope").textContent =
    "Showing " + shown + " of the " + FINDINGS.length + " most recent findings fetched (limit " +
    limit + "). State and severity are filtered in the browser.";
}

async function searchFindings(term) {
  const repoId = $("findings-repo").value;
  if (!repoId) throw new Error("pick a repository first");

  const terms = usableSearchTerms(term);
  if (terms.length === 0) {
    // The server would return an empty list here, which reads as "no
    // matches" when the real problem is the query.
    FINDINGS = [];
    applyFindingFilters();
    $("findings-scope").textContent =
      "Enter at least one term of two or more characters. Punctuation like \" * : ( ) ' is stripped.";
    return;
  }

  const body = await api(
    "GET",
    "/api/repos/" + repoId + "/findings/search?limit=100&q=" + encodeURIComponent(term)
  );
  FINDINGS = body.findings || [];
  const shown = applyFindingFilters();
  $("findings-scope").textContent =
    "Top " + shown + " of " + FINDINGS.length +
    " matches by relevance (not recency), searching title, description and file path only. " +
    "All terms must appear.";
}

// --------------------------------------------------------------------- views

function switchView(view) {
  CURRENT_VIEW = view;
  for (const button of document.querySelectorAll("#tabs button")) {
    if (button.dataset.view === view) button.setAttribute("aria-current", "true");
    else button.removeAttribute("aria-current");
  }
  for (const name of ["repos", "jobs", "findings"]) {
    $("view-" + name).hidden = name !== view;
  }
  schedulePoll();
  guarded(() => refreshView());
}

async function refreshView() {
  if (CURRENT_VIEW === "repos") {
    // The app status comes first: the rows' GitHub actions depend on it.
    await loadGithubApp();
    return loadRepos();
  }
  if (CURRENT_VIEW === "jobs") return loadJobs();
  if (CURRENT_VIEW === "findings") {
    if (REPOS.length === 0) await loadRepos();
    return loadFindings();
  }
}

/** Poll only the visible view, and only while the tab is visible.
 *  Every request the dashboard makes lands on the server's single
 *  database connection and also stamps workers.last_seen_at, so idle
 *  polling contends directly with worker lease traffic. */
function schedulePoll() {
  if (POLL_TIMER !== null) {
    window.clearTimeout(POLL_TIMER);
    POLL_TIMER = null;
  }
  const generation = ++POLL_GENERATION;
  const wanted = CURRENT_VIEW === "jobs" && $("jobs-auto").checked;
  if (!wanted) return;
  const delay = Math.max(1, CONFIG.poll_seconds) * 1000;
  const poll = async () => {
    POLL_TIMER = null;
    if (generation !== POLL_GENERATION) return;
    if (document.visibilityState === "visible") {
      await guarded(() => loadJobs());
    }
    if (
      generation === POLL_GENERATION &&
      CURRENT_VIEW === "jobs" &&
      $("jobs-auto").checked
    ) {
      POLL_TIMER = window.setTimeout(poll, delay);
    }
  };
  POLL_TIMER = window.setTimeout(poll, delay);
}

// ----------------------------------------------------------------------- init

function wireUp() {
  for (const button of document.querySelectorAll("#tabs button")) {
    button.addEventListener("click", () => switchView(button.dataset.view));
  }

  $("repos-refresh").addEventListener("click", () => guarded(() => loadRepos()));
  $("repo-add-toggle").addEventListener("click", () => {
    const form = $("repo-add");
    form.hidden = !form.hidden;
    // The app may have been set or cleared with loupectl since the view
    // loaded; the hint should describe what a submit will actually do.
    if (!form.hidden) guarded(() => loadGithubApp());
  });
  for (const button of document.querySelectorAll("[data-cancel]")) {
    button.addEventListener("click", () => {
      $(button.dataset.cancel).hidden = true;
    });
  }
  for (const radio of document.querySelectorAll("#repo-add input[name=reporting]")) {
    radio.addEventListener("change", () => {
      for (const block of document.querySelectorAll("#repo-add [data-reporting]")) {
        block.hidden = block.dataset.reporting !== radio.value || !radio.checked;
      }
      applyGithubAuthHint();
    });
  }
  $("repo-add").addEventListener("submit", (event) => {
    event.preventDefault();
    guarded(async () => {
      const payload = readRepoForm(event.target);
      await api("POST", "/api/repos", payload);
      event.target.reset();
      $("repo-add").hidden = true;
      await loadRepos();
    });
  });

  $("jobs-refresh").addEventListener("click", () => guarded(() => loadJobs()));
  $("jobs-kind").addEventListener("change", () => guarded(() => loadJobs()));
  $("jobs-limit").addEventListener("change", () => guarded(() => loadJobs()));
  $("jobs-auto").addEventListener("change", schedulePoll);

  $("findings-refresh").addEventListener("click", () => guarded(() => loadFindings()));
  $("findings-repo").addEventListener("change", () => guarded(() => loadFindings()));
  $("findings-state").addEventListener("change", applyFindingFilters);
  $("findings-severity").addEventListener("change", applyFindingFilters);
  $("findings-limit").addEventListener("change", () => guarded(() => loadFindings()));
  $("findings-search-form").addEventListener("submit", (event) => {
    event.preventDefault();
    const term = $("findings-search").value.trim();
    if (term === "") return guarded(() => loadFindings());
    guarded(() => searchFindings(term));
  });
  $("findings-search-clear").addEventListener("click", () => {
    $("findings-search").value = "";
    guarded(() => loadFindings());
  });

  document.addEventListener("visibilitychange", () => {
    if (document.visibilityState === "visible" && CURRENT_VIEW === "jobs") {
      guarded(() => loadJobs());
    }
  });
}

async function boot() {
  bootstrapCapability();
  wireUp();
  try {
    CONFIG = await api("GET", "/api/config");
  } catch (e) {
    banner("Could not load dashboard config: " + (e.message || e));
    return;
  }
  await refreshStatus();
  switchView("repos");
}

boot();
