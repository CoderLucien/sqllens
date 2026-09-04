const state = { aiOk: false };

const DEMOS = [
  {
    title: "样例一 · 索引访问",
    desc: "index_orders 全表扫描 · 20 次/分钟 · 65,537 keys/次（真实 A/B：加索引后 2 keys）",
    evidence: {
      schema_version: "evidence/v3",
      sql: { sql_digest: "8c27725d5bb319605ec7433f114ddde077401dc4f62174fc58861eee73705f83", database: "sqllens_m0_lab", table_name: "index_orders" },
      runtime: { exec_count: 20, window_minutes: 60, p95_ms: 66, avg_total_keys: 65537, scanned_rows: 65537, result_rows: 1 },
      plan: { operator_rows: [{ operator: "TableFullScan", table: "index_orders", est_rows: 65537 }] },
      stats: { est_rows: 32768, actual_rows: 65536, healthy: 100 },
      schema: { filter_columns: ["customer_id", "state"], indexes: [{ name: "PRIMARY", columns: ["id"] }] },
      optional: { baseline_weighted_keys: 1310740, reduced_weighted_keys: 327685 },
    },
  },
  {
    title: "样例二 · 统计偏差",
    desc: "stats_orders 估算 62,947 vs 实际 131,072 · 健康度 0（ANALYZE 后恢复 100）",
    evidence: {
      schema_version: "evidence/v3",
      sql: { sql_digest: "3ac8c5f1e112d4e6a9b8c7d6e5f4a3b2c1d0e9f8a7b6c5d4e3f2a1b0c9d8e7f6", database: "sqllens_m0_lab", table_name: "stats_orders" },
      runtime: { exec_count: 1, window_minutes: 60, p95_ms: 10 },
      plan: { operator_rows: [{ operator: "TableFullScan", table: "stats_orders", est_rows: 62947 }] },
      stats: { est_rows: 62947, actual_rows: 131072, healthy: 0 },
      schema: { filter_columns: ["sku"], indexes: [{ name: "PRIMARY", columns: ["id"] }] },
      optional: { batch_before_min: 4, batch_target_min: 2 },
    },
  },
  {
    title: "样例三 · 热点重复",
    desc: "同一 SQL 一分钟窗口 20 次全表扫描 · 加权 131 万 keys（削减实测 -75%）",
    evidence: {
      schema_version: "evidence/v3",
      sql: { sql_digest: "8c27725d5bb319605ec7433f114ddde077401dc4f62174fc58861eee73705f83", database: "sqllens_m0_lab", table_name: "index_orders" },
      runtime: { exec_count: 20, window_minutes: 60, p95_ms: 66, avg_total_keys: 65537, scanned_rows: 65537, result_rows: 1 },
      plan: { operator_rows: [{ operator: "TableFullScan", table: "index_orders", est_rows: 65537 }] },
      stats: { est_rows: 32768, actual_rows: 65536, healthy: 100 },
      schema: { filter_columns: [], indexes: [{ name: "PRIMARY", columns: ["id"] }] },
      optional: { baseline_weighted_keys: 1310740, reduced_weighted_keys: 327685 },
    },
  },
];

function el(id) { return document.getElementById(id); }
function esc(text) {
  return String(text).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
}
function toast(msg) {
  let t = document.querySelector(".toast");
  if (!t) {
    t = document.createElement("div");
    t.className = "toast";
    document.body.appendChild(t);
  }
  t.textContent = msg;
  t.classList.add("visible");
  clearTimeout(t._h);
  t._h = setTimeout(() => t.classList.remove("visible"), 2200);
}

function go(i) {
  document.querySelectorAll(".screen").forEach((s, x) => s.classList.toggle("active", x === i));
  document.querySelectorAll(".step").forEach((s, x) => { s.classList.toggle("active", x === i); s.classList.toggle("done", x < i); });
  window.scrollTo({ top: 0, behavior: "smooth" });
}
function inTab(i) {
  document.querySelectorAll("#scr-input .tab").forEach((t, x) => t.classList.toggle("active", x === i));
  ["inp0", "inp1", "inp2"].forEach((id, x) => el(id).classList.toggle("active", x === i));
}
async function copyDumpScript() {
  try { await navigator.clipboard.writeText(el("dumpScript").textContent); toast("DUMP 脚本已复制"); }
  catch { toast("浏览器未开放剪贴板权限，请手动复制"); }
}
function useRules() {
  state.aiOk = false;
  el("reportMode").className = "alert info";
  el("reportMode").innerHTML = "当前版本报告均由规则引擎生成；AI 归纳为后续能力。";
  go(2);
}

async function postJson(url, body) {
  const response = await fetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  let data = null;
  try { data = await response.json(); } catch { data = null; }
  if (!response.ok) {
    throw new Error((data && data.message) ? data.message : `请求失败：HTTP ${response.status}`);
  }
  return data;
}

const PROGRESS_STAGES = ["上传诊断包", "解析 Replayer", "提取证据", "生成结论", "完成"];

function setProgress(container, currentIndex, doneThrough) {
  const items = PROGRESS_STAGES.map((label, index) => {
    let cls = "p-step";
    let mark = "";
    if (index < doneThrough || (index === currentIndex && doneThrough === index)) {
      if (index < currentIndex) { cls += " done"; mark = "✓ "; }
    }
    if (index === currentIndex && doneThrough !== index) cls += " active";
    if (index === currentIndex && doneThrough === index) { cls += " done"; mark = "✓ "; }
    return `<span class="${cls}">${mark}${label}</span>`;
  });
  container.innerHTML = `<div class="p-steps">${items.join('<span class="p-arrow">→</span>')}</div>`;
}

async function diagnose(evidence, progressContainer) {
  try {
    if (progressContainer) setProgress(progressContainer, 3, 2);
    const report = await postJson("/api/v1/v4/diagnose", evidence);
    if (progressContainer) setProgress(progressContainer, 4, 4);
    renderReport(report);
    go(2);
  } catch (error) {
    if (progressContainer) progressContainer.innerHTML = `<div class="alert err">诊断失败：${esc(error.message)}</div>`;
    toast(`诊断失败：${error.message}`);
  }
}

function renderReport(report) {
  state.report = report;
  const mode = el("reportMode");
  if (report.mode === "rules") { mode.className = "alert info"; mode.textContent = report.ai_status_zh; }
  else if (report.mode === "degraded") { mode.className = "alert warn"; mode.textContent = report.ai_status_zh; }
  else { mode.className = "alert ok"; mode.textContent = report.ai_status_zh; }

  const sections = report.sections;
  const priorityBadge = report.priority === "P1" ? '<span class="badge p1">P1</span>' : '<span class="badge p2">P2</span>';
  const modeBadge =
    report.mode === "rules" ? '<span class="badge mode-rule">规则生成</span>'
      : report.mode === "degraded" ? '<span class="badge mode-degraded">AI 失败已降级</span>'
        : '<span class="badge mode-ai">AI 增强</span>';
  const ruleBadges = (sections.conclusion.rule_ids || []).map((id) => `<span class="badge src">${esc(id)}</span>`).join("");

  const evidenceRows = (sections.evidence || []).map((row) =>
    `<tr><td>${esc(row.label_zh)}</td><td>${esc(row.value_zh)}</td><td>${esc((row.evidence_ids || []).join(", "))}</td></tr>`
  ).join("");

  const changes = (sections.changes || []).length
    ? (sections.changes || []).map((change) => `
    <div class="four">
      <div class="kv"><b>变更操作</b><span>${esc(change.operation_zh)}</span></div>
      <div class="kv"><b>风险提示</b><span>${esc(change.risk_zh)}</span></div>
      <div class="kv"><b>成本预估</b><span>${esc(change.cost_zh)}<span class="formula">${esc(change.cost_formula_zh)}</span></span></div>
      <div class="kv"><b>收益预估</b><span>${esc(change.gain_zh)}<span class="formula">${esc(change.gain_formula_zh)}</span></span></div>
    </div>`).join("")
    : '<div class="alert info">本次未给出变更建议：证据未命中已知异常模式。如需进一步分析，可补充运行时证据（如直连采集执行次数与延迟）后重新诊断。</div>';

  const validations = (sections.validation || []).map((item) => `<li>${esc(item.text_zh)}</li>`).join("");
  const rollbacks = (sections.rollback || []).map((item) => `<li>${esc(item.text_zh)}</li>`).join("");

  el("reportBody").innerHTML = `
    <div class="h-seg"><span class="no">一</span>结论 ${priorityBadge}${modeBadge}${ruleBadges}</div>
    <p>${esc(sections.conclusion.text_zh)}</p>
    <div class="hint">SQL Digest：${esc(report.sql_digest.slice(0, 16))}… · 数据库：${esc(report.database)}</div>

    <div class="h-seg"><span class="no">二</span>证据</div>
    <table><tr><th>证据</th><th>内容</th><th>证据 ID</th></tr>${evidenceRows}</table>

    <div class="h-seg"><span class="no">三</span>问题分析</div>
    <p>${esc(sections.analysis.text_zh)}</p>

    <div class="h-seg"><span class="no">四</span>变更建议 <span class="badge src">规则 + 确定性估算</span></div>
    ${changes}

    <div class="h-seg"><span class="no">五</span>验证方法</div>
    <ul class="plain-list">${validations}</ul>

    <div class="h-seg"><span class="no">六</span>回滚步骤</div>
    <ul class="plain-list">${rollbacks}</ul>`;
}

async function aiTest() {
  const baseUrl = el("baseUrl").value.trim();
  const apiKey = el("apiKey").value.trim();
  const model = el("model").value.trim();
  if (!baseUrl || !apiKey || !model) {
    el("aiMsg").innerHTML = '<div class="alert err">请先填写 Base URL、API Key 与模型名。</div>';
    return;
  }
  el("aiBusy").innerHTML = '<span class="spin"></span>';
  try {
    const result = await postJson("/api/v1/v4/ai/test", { base_url: baseUrl, api_key: apiKey, model, protocol: el("proto").value });
    state.aiOk = !!result.ok;
    el("aiMsg").innerHTML = `<div class="alert ${result.ok ? "ok" : "err"}">${esc(result.message_zh)}</div>`;
    if (result.ok) toast("AI 连接测试通过");
  } catch (error) {
    state.aiOk = false;
    el("aiMsg").innerHTML = `<div class="alert err">${esc(error.message)}</div>`;
  } finally {
    el("aiBusy").innerHTML = "";
  }
}

async function aiList() {
  const baseUrl = el("baseUrl").value.trim();
  const apiKey = el("apiKey").value.trim();
  if (!baseUrl || !apiKey) {
    el("aiMsg").innerHTML = '<div class="alert err">请先填写 Base URL 与 API Key。</div>';
    return;
  }
  el("aiBusy").innerHTML = '<span class="spin"></span>';
  try {
    const result = await postJson("/api/v1/v4/ai/models", { base_url: baseUrl, api_key: apiKey, model: el("model").value.trim() || "placeholder", protocol: el("proto").value });
    if (result.ok && result.models && result.models.length) {
      const options = result.models.map((m) => `<option value="${esc(m)}">${esc(m)}</option>`).join("");
      el("aiMsg").innerHTML = `<div class="alert ok">${esc(result.message_zh)} 选择：<select id="modelPick" style="width:auto;display:inline-block">${options}</select></div>`;
      el("modelPick").addEventListener("change", (e) => { el("model").value = e.target.value; toast(`已选择模型 ${e.target.value}`); });
    } else {
      el("aiMsg").innerHTML = `<div class="alert err">${esc(result.message_zh || "未识别到可用模型。")}</div>`;
    }
  } catch (error) {
    el("aiMsg").innerHTML = `<div class="alert err">${esc(error.message)}</div>`;
  } finally {
    el("aiBusy").innerHTML = "";
  }
}

function init() {
  el("demoList").innerHTML = DEMOS.map((demo, index) =>
    `<div class="demo-card" data-index="${index}"><b>${esc(demo.title)}</b><span>${esc(demo.desc)}</span></div>`
  ).join("");
  document.querySelectorAll(".demo-card").forEach((card) => {
    card.addEventListener("click", () => diagnose(DEMOS[Number(card.dataset.index)].evidence));
  });

  el("zipInput").addEventListener("change", async (event) => {
    const file = event.target.files && event.target.files[0];
    if (!file) return;
    const busy = el("uploadMsg");
    setProgress(busy, 0, 0);
    try {
      const response = await fetch("/api/v1/v4/plan-replayer", { method: "POST", body: file });
      let data = null;
      try { data = await response.json(); } catch { data = null; }
      if (!response.ok) throw new Error((data && data.message) ? data.message : `上传失败：HTTP ${response.status}`);
      setProgress(busy, 2, 1);
      await diagnose(data, busy);
    } catch (error) {
      busy.innerHTML = `<div class="alert err">上传失败：${esc(error.message)}</div>`;
      toast(`上传失败：${error.message}`);
    }
  });

  document.querySelectorAll(".steps .step").forEach((step, i) => step.addEventListener("click", () => go(i)));
  document.querySelectorAll("#scr-input .tab").forEach((tab, i) => tab.addEventListener("click", () => inTab(i)));
  document.querySelectorAll("#scr-input .btn").forEach((button) => {
    if (button.textContent.includes("复制脚本")) button.addEventListener("click", copyDumpScript);
    if (button.textContent.includes("下一步")) button.addEventListener("click", () => go(1));
  });
  document.querySelectorAll("#scr-ai .btn").forEach((button) => {
    if (button.textContent.includes("连接测试")) button.addEventListener("click", aiTest);
    else if (button.textContent.includes("识别模型")) button.addEventListener("click", aiList);
    else if (button.textContent.includes("跳过")) button.addEventListener("click", useRules);
    else if (button.textContent.includes("开始诊断")) button.addEventListener("click", () => go(2));
    else if (button.textContent.includes("← 返回")) button.addEventListener("click", () => go(0));
  });
  document.querySelectorAll("#scr-report .btn").forEach((button) => {
    if (button.id === "restartBtn") button.addEventListener("click", () => go(0));
    else if (button.id === "copyReportBtn") button.addEventListener("click", copyReport);
  });
}

function copyReport() {
  if (!state.report) {
    toast("尚无报告可复制");
    return;
  }
  const r = state.report;
  const modeName = r.mode === "rules" ? "规则生成" : r.mode === "degraded" ? "AI 失败已降级" : "AI 增强";
  const lines = [
    `SQLLens 诊断报告（${r.priority} · ${modeName}）`,
    "",
    `一、结论：${r.sections.conclusion.text_zh}`,
    "",
    "二、证据：" + (r.sections.evidence || []).map((e) => `${e.label_zh}：${e.value_zh}`).join("；"),
    "",
    `三、问题分析：${r.sections.analysis.text_zh}`,
    "",
    "四、变更建议：" + ((r.sections.changes || []).map((c, i) =>
      `\n${i + 1}. 操作：${c.operation_zh}\n   风险：${c.risk_zh}\n   成本：${c.cost_zh}\n   收益：${c.gain_zh}`).join("") || "无（未命中已知异常模式）"),
    "",
    "五、验证方法：" + (r.sections.validation || []).map((v) => v.text_zh).join("；"),
    "",
    "六、回滚步骤：" + (r.sections.rollback || []).map((v) => v.text_zh).join("；"),
  ];
  navigator.clipboard.writeText(lines.join("\n")).then(
    () => toast("报告已复制到剪贴板"),
    () => toast("复制失败，请手动选择复制"),
  );
}

init();
