import {
  Activity,
  AlertTriangle,
  CheckCircle2,
  ClipboardList,
  FileSearch,
  LoaderCircle,
  RotateCcw,
  ShieldCheck
} from "lucide-react";
import { FormEvent, useMemo, useState } from "react";

import {
  ApiClientError,
  apiRequest,
  DiagnosisCase,
  DiagnosisExplanation,
  DiagnosisJob
} from "./api";

const MAX_SQL_BYTES = 65_536;

const MISSING_EVIDENCE_LABELS: Record<string, string> = {
  tidb_version: "TiDB 版本",
  schema: "Schema 元数据",
  statistics: "统计信息",
  ordinary_plan: "普通执行计划",
  runtime_metrics: "运行指标"
};

const COMPLETENESS_LABELS = {
  insufficient: "证据不足",
  partial: "证据部分完整",
  sufficient: "证据完整"
} as const;

const RISK_LABELS = {
  low: "低风险",
  medium: "中风险",
  high: "高风险",
  critical: "严重风险"
} as const;

interface DiagnosisWorkspaceProps {
  csrfToken: string;
  modelMode: "external" | "rules";
  onAuthRequired?: () => void;
}

export function DiagnosisWorkspace({
  csrfToken,
  modelMode,
  onAuthRequired
}: DiagnosisWorkspaceProps) {
  const [sql, setSql] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [job, setJob] = useState<DiagnosisJob | null>(null);
  const [diagnosisCase, setDiagnosisCase] = useState<DiagnosisCase | null>(null);
  const byteCount = useMemo(() => new TextEncoder().encode(sql).byteLength, [sql]);
  const inputTooLarge = byteCount > MAX_SQL_BYTES;
  const canSubmit = sql.trim().length > 0 && !inputTooLarge && !busy;

  function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!canSubmit) {
      return;
    }
    setBusy(true);
    setError(null);
    setJob(null);
    setDiagnosisCase(null);
    void (async () => {
      try {
        const created = await apiRequest<DiagnosisJob>(
          "/api/v1/cases/sql",
          {
            method: "POST",
            headers: { "Idempotency-Key": createIdempotencyKey() },
            body: JSON.stringify({ sql })
          },
          csrfToken
        );
        const fetched = await apiRequest<DiagnosisCase>(
          `/api/v1/cases/${encodeURIComponent(created.caseId)}`
        );
        setJob(created);
        setDiagnosisCase(fetched);
      } catch (requestError) {
        if (requestError instanceof ApiClientError && requestError.code === "AUTH_REQUIRED") {
          onAuthRequired?.();
        }
        setError(messageFor(requestError));
      } finally {
        setBusy(false);
      }
    })();
  }

  return (
    <div className="diagnosis-workbench">
      <header className="diagnosis-heading">
        <div>
          <p className="eyebrow">Layer 1 · SQL</p>
          <h1 id="ready-title">诊断工作台已就绪</h1>
          <p className="diagnosis-subtitle">
            当前模式：{modelMode === "external" ? "外部模型增强" : "本地规则"}
          </p>
        </div>
        <span className="mode-indicator">
          <Activity aria-hidden="true" size={16} />
          {modelMode === "external" ? "External" : "Rules"}
        </span>
      </header>

      <div className="diagnosis-layout">
        <section className="sql-editor-panel" aria-labelledby="sql-editor-title">
          <div className="panel-heading">
            <div>
              <p className="panel-kicker">输入</p>
              <h2 id="sql-editor-title">SQL</h2>
            </div>
            <span
              className={inputTooLarge ? "byte-count byte-count-error" : "byte-count"}
              id="sql-byte-count"
            >
              {byteCount.toLocaleString()} / 65,536 B
            </span>
          </div>

          <form className="sql-form" onSubmit={submit}>
            <label className="visually-hidden" htmlFor="diagnosis-sql">SQL</label>
            <textarea
              aria-describedby="sql-byte-count sql-input-error"
              aria-invalid={inputTooLarge}
              autoCapitalize="off"
              autoCorrect="off"
              id="diagnosis-sql"
              onChange={(event) => {
                setSql(event.target.value);
                setError(null);
              }}
              placeholder="SELECT ..."
              spellCheck={false}
              value={sql}
            />
            <div className="sql-form-footer">
              <span className="input-error" id="sql-input-error">
                {inputTooLarge ? "输入超过 64 KiB 限制" : ""}
              </span>
              <button className="button button-primary" disabled={!canSubmit} type="submit">
                {busy ? (
                  <LoaderCircle aria-hidden="true" className="spin" size={18} />
                ) : (
                  <FileSearch aria-hidden="true" size={18} />
                )}
                生成诊断案例
              </button>
            </div>
          </form>

          {error && (
            <div className="alert alert-error diagnosis-error" role="alert">
              <AlertTriangle aria-hidden="true" size={18} />
              <span>{error}</span>
            </div>
          )}
        </section>

        <section className="case-result-panel" aria-label="诊断结果" aria-live="polite">
          {busy ? (
            <div className="case-state" role="status">
              <LoaderCircle aria-hidden="true" className="spin" size={24} />
              <strong>正在生成诊断案例</strong>
            </div>
          ) : diagnosisCase && job ? (
            <CaseResult diagnosisCase={diagnosisCase} explanation={job.explanation} />
          ) : (
            <div className="case-state case-state-empty">
              <ClipboardList aria-hidden="true" size={26} />
              <strong id="case-result-title">尚无诊断案例</strong>
            </div>
          )}
        </section>
      </div>
    </div>
  );
}

function CaseResult({
  diagnosisCase,
  explanation
}: {
  diagnosisCase: DiagnosisCase;
  explanation: DiagnosisExplanation;
}) {
  const completeness = diagnosisCase.evidenceCompleteness;
  return (
    <div className="case-result">
      <header className="case-header">
        <div>
          <p className="panel-kicker">Diagnosis Case</p>
          <h2 id="case-result-title">诊断案例</h2>
          <code>{diagnosisCase.caseId}</code>
        </div>
        <ExplanationBadge explanation={explanation} />
      </header>

      <section className="case-section completeness-section" aria-labelledby="completeness-title">
        <div className="section-title-row">
          <h2 id="completeness-title">证据完整度</h2>
          <strong>{Math.round(completeness.score * 100)}%</strong>
        </div>
        <div className={`completeness-status completeness-${completeness.classification}`}>
          <AlertTriangle aria-hidden="true" size={16} />
          <span>{COMPLETENESS_LABELS[completeness.classification]}</span>
        </div>
        {completeness.missing.length > 0 && (
          <ul className="missing-evidence" aria-label="缺失证据">
            {completeness.missing.map((item) => (
              <li key={item}>{MISSING_EVIDENCE_LABELS[item] ?? item}</li>
            ))}
          </ul>
        )}
      </section>

      <section className="case-section" aria-labelledby="evidence-title">
        <div className="section-title-row">
          <h2 id="evidence-title">证据</h2>
          <span>{diagnosisCase.evidence.length}</span>
        </div>
        <div className="evidence-list">
          {diagnosisCase.evidence.map((evidence) => (
            <article className="evidence-row" key={evidence.evidenceId}>
              <div className="evidence-meta">
                <span>{evidence.kind === "sql_structure" ? "SQL 结构" : evidence.kind}</span>
                <code>{evidence.evidenceId}</code>
              </div>
              <p>{evidence.summary}</p>
            </article>
          ))}
        </div>
      </section>

      <section className="case-section" aria-labelledby="hypotheses-title">
        <div className="section-title-row">
          <h2 id="hypotheses-title">候选假设</h2>
          <span>{diagnosisCase.hypotheses.length}</span>
        </div>
        <ol className="hypothesis-list">
          {diagnosisCase.hypotheses.map((hypothesis, index) => (
            <li key={hypothesis.hypothesisId}>
              <div className="hypothesis-meta">
                <span>候选 {index + 1}</span>
                <span>低置信度 · {Math.round(hypothesis.confidence * 100)}%</span>
              </div>
              <p>{hypothesis.statement}</p>
              <div className="evidence-links">
                {hypothesis.supportingEvidenceIds.map((evidenceId) => (
                  <code key={evidenceId}>{evidenceId}</code>
                ))}
              </div>
            </li>
          ))}
        </ol>
      </section>

      {diagnosisCase.recommendations.map((recommendation) => (
        <section
          className="case-section recommendation-section"
          aria-labelledby={`recommendation-${recommendation.recommendationId}`}
          key={recommendation.recommendationId}
        >
          <div className="recommendation-heading">
            <div>
              <p className="panel-kicker">建议</p>
              <h2 id={`recommendation-${recommendation.recommendationId}`}>
                {recommendation.title}
              </h2>
            </div>
            <span className={`risk-label risk-${recommendation.risk}`}>
              {RISK_LABELS[recommendation.risk]}
            </span>
          </div>
          <p className="recommendation-rationale">{recommendation.rationale}</p>
          {recommendation.requiresHumanApproval && (
            <div className="approval-boundary">
              <ShieldCheck aria-hidden="true" size={16} />
              <span>需人工确认</span>
            </div>
          )}
          <div className="action-columns">
            <div>
              <h3><CheckCircle2 aria-hidden="true" size={16} />验证</h3>
              <ul>
                {recommendation.validation.map((item) => <li key={item}>{item}</li>)}
              </ul>
            </div>
            <div>
              <h3><RotateCcw aria-hidden="true" size={16} />回滚</h3>
              <ul>
                {recommendation.rollback.map((item) => <li key={item}>{item}</li>)}
              </ul>
            </div>
          </div>
        </section>
      ))}

      <footer className="case-revisions">
        <span>{diagnosisCase.pinnedRevisions.parser}</span>
        <span>{diagnosisCase.pinnedRevisions.ruleSet}</span>
      </footer>
    </div>
  );
}

function ExplanationBadge({ explanation }: { explanation: DiagnosisExplanation }) {
  if (explanation.status === "applied") {
    return (
      <div className="explanation-badge explanation-applied">
        <CheckCircle2 aria-hidden="true" size={15} />
        <span>模型已排序</span>
      </div>
    );
  }
  if (explanation.status === "degraded") {
    return (
      <div className="explanation-stack">
        <div className="explanation-badge explanation-degraded">
          <AlertTriangle aria-hidden="true" size={15} />
          <span>规则结果 · 模型不可用</span>
        </div>
        {explanation.code && <code>{explanation.code}</code>}
      </div>
    );
  }
  return (
    <div className="explanation-badge">
      <ShieldCheck aria-hidden="true" size={15} />
      <span>规则结果</span>
    </div>
  );
}

function createIdempotencyKey(): string {
  if (typeof crypto.randomUUID === "function") {
    return `web-${crypto.randomUUID()}`;
  }
  const random = new Uint8Array(16);
  crypto.getRandomValues(random);
  return `web-${Array.from(random, (value) => value.toString(16).padStart(2, "0")).join("")}`;
}

function messageFor(error: unknown): string {
  if (error instanceof ApiClientError) {
    return error.message;
  }
  return "无法生成诊断案例，请确认本地服务仍在运行。";
}
