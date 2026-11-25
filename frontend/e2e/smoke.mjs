// Browser smoke test. Needs both servers running and completed experiments. Uses the installed Edge, or set BG_E2E_CHANNEL=chrome.
import { mkdirSync } from "node:fs";
import { chromium } from "playwright-core";

const BASE = process.env.BG_E2E_BASE ?? "http://localhost:3000";
const OUT = process.argv[2] ?? ".e2e-output";
mkdirSync(OUT, { recursive: true });
const browser = await chromium.launch({ channel: process.env.BG_E2E_CHANNEL ?? "msedge", headless: true });
const page = await browser.newPage({ viewport: { width: 1440, height: 1000 } });
const problems = [];
// The test triggers one 409 on purpose (a reserved policy name). The browser logs every failed request, so that one is expected.
const expected = [/status of 409/];
page.on("console", (m) => { if (m.type() === "error" && !expected.some((r) => r.test(m.text()))) problems.push(`console: ${m.text()}`); });
page.on("pageerror", (e) => problems.push(`pageerror: ${e.message}`));
page.on("response", (r) => { if (r.status() >= 500) problems.push(`HTTP ${r.status()} ${r.url()}`); });

const results = [];
function check(name, ok, detail = "") {
  results.push(`${ok ? "PASS" : "FAIL"} ${name}${detail ? ` - ${detail}` : ""}`);
}
const api = async (path) => (await page.request.get(`${BASE}/api/v1${path}`)).json();

const pages = [["overview", "/", "Security overview"], ["runs", "/trace", "Live runs"], ["experiments", "/experiments", "Experiments"],
  ["model", "/model", "Risk model"], ["policies", "/policies", "Policy management"], ["audit", "/audit", "Audit log"]];
for (const [name, path, heading] of pages) {
  await page.goto(BASE + path, { waitUntil: "networkidle" });
  await page.waitForSelector(`h1:has-text("${heading}")`, { timeout: 15000 });
  await page.screenshot({ path: `${OUT}/${name}.png`, fullPage: true });
  check(`page ${name}`, true);
}

// Overview: run accounting adds up and matches the API.
const overview = await api("/overview");
await page.goto(BASE, { waitUntil: "networkidle" });
const overviewText = await page.innerText("main");
check("overview total matches API", overviewText.includes(overview.runs.total.toLocaleString("en-US")), String(overview.runs.total));
check("overview parts add up", overview.runs.total === overview.runs.experiment_runs + overview.runs.live_runs);
check("overview headline uses the active model", !overview.latest_experiment?.manifest.model || overview.latest_experiment.manifest.model.version === (await api("/ml/model")).version);

// Experiment results: displayed values come from the API for the held-out split.
const experiments = await api("/experiments");
// The experiments that used the active model, which are the reported results.
const active = (await api("/ml/model")).version;
const reported = (e) => e.status === "completed" && e.manifest.model?.version === active && e.config.configurations.includes("RC");
const internal = experiments.find((e) => reported(e) && e.manifest.suite !== "injecagent");
const external = experiments.find((e) => reported(e) && e.manifest.suite === "injecagent");
for (const [label, experiment, split] of [["internal", internal, "holdout"], ["external", external, "external"]]) {
  if (!experiment) { check(`results ${label}`, false, "no completed experiment"); continue; }
  const compare = await api(`/analytics/compare?experiment_id=${experiment.id}&split=${split}`);
  await page.goto(`${BASE}/experiments/${experiment.id}`, { waitUntil: "networkidle" });
  await page.waitForSelector("text=Results by configuration", { timeout: 20000 });
  await page.waitForTimeout(500);
  const text = await page.innerText("main");
  const expected = `${(compare.overall.attack_prevention_rate.E.value * 100).toFixed(1)}%`;
  check(`results ${label} shows measured value for E`, text.includes(expected), expected);
  check(`results ${label} labels targets as goals`, text.includes("Proposal target (a goal)"));
  await page.screenshot({ path: `${OUT}/results_${label}.png`, fullPage: true });
  await page.click('button[role="tab"]:has-text("Scenarios")');
  await page.waitForSelector("tbody tr td a", { timeout: 20000 });
  check(`scenario matrix ${label}`, (await page.locator("tbody tr").count()) > 0);
}
await page.locator('[tabindex="0"]').first().hover().catch(() => undefined);

// Old analytics links land on an experiment.
await page.goto(`${BASE}/analytics`, { waitUntil: "networkidle" });
await page.waitForURL(/\/experiments\/[a-f0-9]+/, { timeout: 15000 });
check("analytics redirect", true);

// Risk model page reflects the bundle metadata.
const model = await api("/ml/model");
await page.goto(`${BASE}/model`, { waitUntil: "networkidle" });
const modelText = await page.innerText("main");
check("model version shown", model.available && modelText.includes(model.version), model.version ?? model.problem);
const stateful = model.metadata.profiles.stateful;
if (stateful.test) {
  check("model test PR-AUC shown", modelText.includes(stateful.test.hybrid.pr_auc.toFixed(3)));
} else {
  // A model without an untouched test evaluation must say so rather than show a number.
  check("model without test result says so", modelText.includes("not evaluated on the test split") && !model.metadata.test_evaluated);
}

// Live run with a human approval through the real UI. ru06 is an approvable, out-of-scope write.
await page.goto(`${BASE}/trace`, { waitUntil: "domcontentloaded" });
await page.waitForSelector('label:has-text("Scenario") select option[value="pi01_readme_env_exfil"]', { state: "attached", timeout: 30000 });
await page.selectOption('label:has-text("Scenario") select', "ru06_irrelevant_write");
await page.selectOption('label:has-text("Configuration") select', "RC");
await page.selectOption('label:has-text("When approval is required") select', "human");
await page.click('button:has-text("Start run")');
await page.waitForURL(/\/trace\/[a-f0-9]+/);
await page.waitForSelector('button:has-text("Deny")', { timeout: 20000 });
await page.screenshot({ path: `${OUT}/trace_pending.png`, fullPage: true });
check("approval prompt appears", true);
const pendingRun = page.url();
await page.goto(`${BASE}/trace`, { waitUntil: "domcontentloaded" });
await page.waitForSelector("text=Waiting for your decision", { timeout: 15000 });
check("pending approval listed on live runs", true);
check("navigation shows a pending-approval badge", await page.locator('nav a[href="/trace"] span').first().isVisible());
await page.click('a:has-text("Review")');
await page.waitForURL(pendingRun);
await page.waitForSelector('button:has-text("Deny")', { timeout: 20000 });
await page.click('button:has-text("Deny")');
await page.waitForSelector("text=Approval denied", { timeout: 20000 });
check("denied action does not execute", (await page.innerText("main")).includes("Not executed"));

// ML decision explanation in a trace.
await page.goto(`${BASE}/trace`, { waitUntil: "domcontentloaded" });
await page.waitForSelector('label:has-text("Scenario") select option[value="pi01_readme_env_exfil"]', { state: "attached", timeout: 30000 });
await page.selectOption('label:has-text("Scenario") select', "pi01_readme_env_exfil");
await page.selectOption('label:has-text("Configuration") select', "E");
await page.selectOption('label:has-text("When approval is required") select', "auto_deny");
await page.click('button:has-text("Start run")');
await page.waitForURL(/\/trace\/[a-f0-9]+/);
await page.waitForSelector("text=Completed", { timeout: 30000 });
check("ML trace shows a risk explanation", (await page.innerText("main")).includes("ML risk"));
await page.screenshot({ path: `${OUT}/trace_ml.png`, fullPage: true });

// Policy flow: copy a benchmark policy, change it, save, version, deactivate.
await page.goto(`${BASE}/policies`, { waitUntil: "networkidle" });
await page.waitForSelector('button:has-text("Create a copy")');
check("benchmark policy is locked", await page.locator("textarea").first().isDisabled());
await page.click('button:has-text("Create a copy")');
const unique = `e2e-${Date.now()}`;
await page.fill('label:has-text("Policy name") input', "bad;name");
check("invalid policy name blocks creation", await page.locator('button:has-text("Create policy")').isDisabled());
await page.fill('label:has-text("Policy name") input', "project_standard");
await page.click('button:has-text("Create policy")');
await page.waitForSelector("text=name of a benchmark policy", { timeout: 10000 });
check("reserved policy name rejected by the backend", true);
await page.fill('label:has-text("Policy name") input', unique);
await page.selectOption('select[aria-label="State of read_file"]', "approval");
await page.click('button:has-text("Create policy")');
await page.waitForSelector(`text=Created policy "${unique}"`, { timeout: 10000 });
await page.waitForSelector(`li button:has-text("${unique}")`, { timeout: 10000 });
check("policy created", true, unique);
check("unchanged policy cannot be saved", await page.locator('button:has-text("Save as new version")').isDisabled());
await page.selectOption('select[aria-label="State of write_file"]', "prohibited");
// Leaving with unsaved edits asks first; cancelling keeps the edits.
await page.click('button:has-text("project_standard")');
await page.waitForSelector('dialog[open] >> text=Discard unsaved changes?', { timeout: 5000 });
await page.click('dialog[open] button:has-text("Cancel")');
check("unsaved changes are protected", (await page.locator('select[aria-label="State of write_file"]').inputValue()) === "prohibited");
await page.click('button:has-text("Save as new version")');
await page.waitForSelector("text=as version 2", { timeout: 10000 });
check("policy versioned", true);
await page.getByRole("button", { name: "Deactivate", exact: true }).first().click();
await page.waitForSelector('dialog[open] >> text=Deactivate', { timeout: 5000 });
await page.click('dialog[open] button:has-text("Cancel")');
check("cancelled deactivation keeps the policy", (await page.locator(`button:has-text("${unique}")`).count()) > 0);
await page.getByRole("button", { name: "Deactivate", exact: true }).first().click();
await page.locator("dialog[open]").getByRole("button", { name: "Deactivate", exact: true }).click();
await page.waitForSelector(`text=Deactivated "${unique}"`, { timeout: 10000 });
await page.waitForFunction((n) => ![...document.querySelectorAll("li button")].some((b) => b.textContent.includes(n)), unique, { timeout: 10000 });
check("policy deactivated", true);
await page.check('label:has-text("History") input');
await page.click(`button:has-text("${unique}")`);
await page.click('button:has-text("Restore this version")');
await page.waitForSelector("text=as version 3", { timeout: 10000 });
check("deactivated policy restored from history", true);
await page.getByRole("button", { name: "Deactivate", exact: true }).first().click();
await page.locator("dialog[open]").getByRole("button", { name: "Deactivate", exact: true }).click();
await page.waitForSelector(`text=Deactivated "${unique}"`, { timeout: 10000 });

// Audit search, deep link, expansion and hash verification.
await page.goto(`${BASE}/audit?gt_label=unauthorized`, { waitUntil: "networkidle" });
check("audit deep link applies filter", (await page.locator('label:has-text("Ground truth") select').inputValue()) === "unauthorized");
await page.fill('input[type="search"]', "id_rsa");
await page.selectOption('label:has-text("Decision") select', "BLOCK");
await page.click('button:has-text("Apply")');
// The search runs over every stored decision, so wait for the result rather than a fixed time.
await page.waitForFunction(() => /Decisions \((\d[\d,]*)\)/.test(document.body.innerText) && document.body.innerText.includes("id_rsa"), null, { timeout: 15000 }).catch(() => undefined);
const auditText = await page.innerText("main");
check("audit filter narrows results", auditText.includes("id_rsa") && !auditText.includes("Decisions (0)"));
check("audit filters are kept in the address bar", page.url().includes("q=id_rsa") && page.url().includes("decision=BLOCK"));
await page.locator("tbody tr button[aria-expanded]").first().click();
await page.click('button:has-text("Verify hash chain")');
await page.waitForSelector("text=Chain valid", { timeout: 10000 });
check("audit chain verify from UI", true);
await page.click('button:has-text("Reset")');
await page.waitForFunction(() => !location.search, null, { timeout: 10000 });
check("audit reset clears filters", (await page.inputValue('input[type="search"]')) === "");

// Mobile layout: no horizontal page scroll.
await page.setViewportSize({ width: 390, height: 844 });
const mobile = [...pages, ["experiment", internal ? `/experiments/${internal.id}` : "/experiments"]];
for (const [name, path] of mobile) {
  // Pages poll the API, so the network never goes quiet. Wait for content instead.
  await page.goto(BASE + path, { waitUntil: "domcontentloaded" });
  await page.waitForSelector("main h1", { timeout: 30000 });
  await page.waitForFunction(() => !document.querySelector("main")?.innerText.includes("Loading…"), null, { timeout: 30000 });
  await page.waitForTimeout(500);
  const overflow = await page.evaluate(() => document.documentElement.scrollWidth - window.innerWidth);
  const culprit = overflow > 0 ? await page.evaluate(() => {
    const el = [...document.querySelectorAll("main *")].find((e) => e.getBoundingClientRect().right > window.innerWidth && !e.closest(".overflow-x-auto"));
    return el ? `${el.tagName} ${String(el.className).slice(0, 60)}` : "unknown";
  }) : "";
  check(`mobile ${name}`, overflow <= 0, `overflow ${overflow}px ${culprit}`.trim());
}
await page.screenshot({ path: `${OUT}/mobile_experiment.png` });

await browser.close();
console.log(results.join("\n"));
console.log(problems.length ? `PROBLEMS:\n${[...new Set(problems)].join("\n")}` : "No console errors or 5xx responses.");
if (results.some((line) => line.startsWith("FAIL")) || problems.length) process.exitCode = 1;
