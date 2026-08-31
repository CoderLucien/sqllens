import {
  Activity,
  AlertTriangle,
  ArrowRight,
  Check,
  CheckCircle2,
  Cloud,
  Cpu,
  Database,
  KeyRound,
  LoaderCircle,
  LockKeyhole,
  RefreshCw,
  ShieldCheck
  ,Terminal
} from "lucide-react";
import { FormEvent, useEffect, useMemo, useState } from "react";

import { ApiClientError, apiRequest, SetupStage, SetupStatus } from "./api";
import "./styles.css";

const EMPTY_STATUS: SetupStatus = {
  state: "bootstrap_required",
  initialized: false,
  bootstrap_hash_persisted: false,
  model_mode: null,
  csrf_token: null,
  recovery: {
    required: false,
    action: null,
    reason: null
  },
  local_model: {
    available: false,
    verified: false,
    code: "LOCAL_RUNTIME_UNAVAILABLE",
    message: "No qualified local model runtime is exposed to this service."
  }
};

const STEPS: Array<{ stage: SetupStage; label: string }> = [
  { stage: "bootstrap_required", label: "验证身份" },
  { stage: "security_policy_required", label: "安全策略" },
  { stage: "model_required", label: "模型连接" },
  { stage: "ready", label: "完成" }
];

function stageIndex(stage: SetupStage): number {
  return STEPS.findIndex((step) => step.stage === stage);
}

function ErrorBanner({ message }: { message: string }) {
  return (
    <div className="alert alert-error" role="alert">
      <AlertTriangle aria-hidden="true" size={18} />
      <span>{message}</span>
    </div>
  );
}

function LocalModeStatus() {
  return (
    <section className="local-status" aria-labelledby="local-status-title">
      <div className="status-icon status-icon-muted">
        <Cpu aria-hidden="true" size={19} />
      </div>
      <div>
        <h2 id="local-status-title">本地模型不可用</h2>
        <p>当前容器未检测或验证可用的本地模型运行时。</p>
      </div>
      <span className="status-label">未验证</span>
    </section>
  );
}

export function App() {
  const [status, setStatus] = useState<SetupStatus>(EMPTY_STATUS);
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [bootstrapCode, setBootstrapCode] = useState("");
  const [providerHost, setProviderHost] = useState("api.openai.com");
  const [providerUrl, setProviderUrl] = useState("https://api.openai.com/v1");
  const [model, setModel] = useState("");
  const [apiKey, setApiKey] = useState("");
  const [providerVerified, setProviderVerified] = useState(false);

  const activeIndex = useMemo(() => stageIndex(status.state), [status.state]);

  async function loadStatus() {
    setLoading(true);
    setError(null);
    try {
      setStatus(await apiRequest<SetupStatus>("/api/v1/setup/status"));
    } catch (requestError) {
      setError(messageFor(requestError));
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    void loadStatus();
  }, []);

  async function runAction(action: () => Promise<void>) {
    setBusy(true);
    setError(null);
    try {
      await action();
    } catch (requestError) {
      setError(messageFor(requestError));
    } finally {
      setBusy(false);
    }
  }

  function submitBootstrap(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    void runAction(async () => {
      const result = await apiRequest<{ state: SetupStage; csrf_token: string }>(
        "/api/v1/setup/bootstrap",
        {
          method: "POST",
          body: JSON.stringify({ code: bootstrapCode.trim() })
        }
      );
      setBootstrapCode("");
      setStatus((current) => ({
        ...current,
        state: result.state,
        csrf_token: result.csrf_token
      }));
    });
  }

  function submitPolicy(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    void runAction(async () => {
      await apiRequest<{ state: SetupStage }>(
        "/api/v1/setup/security-policy",
        {
          method: "PUT",
          body: JSON.stringify({
            external_model_egress: true,
            allowed_provider_hosts: [providerHost.trim().toLowerCase()],
            send_sql_text: false
          })
        },
        status.csrf_token
      );
      setStatus((current) => ({ ...current, state: "model_required" }));
    });
  }

  function probeProvider(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    void runAction(async () => {
      await apiRequest<{ status: "verified" }>(
        "/api/v1/setup/model-probes",
        {
          method: "POST",
          body: JSON.stringify({
            mode: "external",
            base_url: providerUrl.trim(),
            api_key: apiKey,
            model: model.trim()
          })
        },
        status.csrf_token
      );
      setApiKey("");
      setProviderVerified(true);
    });
  }

  function finalize(mode: "external" | "rules") {
    void runAction(async () => {
      await apiRequest<{ state: SetupStage; model_mode: "external" | "rules" }>(
        "/api/v1/setup/finalize",
        { method: "POST", body: JSON.stringify({ mode }) },
        status.csrf_token
      );
      setStatus((current) => ({
        ...current,
        state: "ready",
        initialized: true,
        model_mode: mode
      }));
    });
  }

  return (
    <div className="app-shell">
      <header className="topbar">
        <div className="brand-mark" aria-hidden="true">
          <Database size={20} />
        </div>
        <div className="brand-copy">
          <strong>SQLLens</strong>
          <span>本地诊断工作台</span>
        </div>
        <div className="runtime-state">
          <span className="runtime-dot" />
          Web API
        </div>
      </header>

      <div className="workspace">
        <aside className="step-rail" aria-label="初始化进度">
          <p className="rail-title">初始化</p>
          <ol>
            {STEPS.map((step, index) => {
              const complete = index < activeIndex;
              const active = index === activeIndex;
              return (
                <li className={active ? "active" : complete ? "complete" : ""} key={step.stage}>
                  <span className="step-index" aria-hidden="true">
                    {complete ? <Check size={15} /> : index + 1}
                  </span>
                  <span>{step.label}</span>
                </li>
              );
            })}
          </ol>
          <div className="rail-boundary">
            <LockKeyhole aria-hidden="true" size={17} />
            <span>默认仅监听本机</span>
          </div>
        </aside>

        <main className="setup-main">
          <div className="setup-content">
            {loading ? (
              <div className="loading-state" role="status">
                <LoaderCircle className="spin" aria-hidden="true" size={24} />
                <span>读取运行状态</span>
              </div>
            ) : (
              <>
                {error && <ErrorBanner message={error} />}
                {status.recovery.required && (
                  <section aria-labelledby="recovery-title">
                    <div className="section-icon"><Terminal aria-hidden="true" size={22} /></div>
                    <p className="eyebrow">需要本机恢复</p>
                    <h1 id="recovery-title">重新签发初始化码</h1>
                    <p className="section-summary">
                      当前凭据或初始化会话已不可继续。请在 Release 目录执行：
                    </p>
                    <code className="recovery-command">./launch.sh recover-setup</code>
                    <button className="button button-secondary" onClick={() => void loadStatus()} type="button">
                      <RefreshCw size={18} />
                      已恢复，重新检查
                    </button>
                  </section>
                )}
                {!status.recovery.required && status.state === "bootstrap_required" && (
                  <section aria-labelledby="bootstrap-title">
                    <div className="section-icon"><KeyRound aria-hidden="true" size={22} /></div>
                    <p className="eyebrow">步骤 1 / 3</p>
                    <h1 id="bootstrap-title">验证这次本地安装</h1>
                    <p className="section-summary">输入启动器显示的一次性初始化码。</p>
                    <form className="setup-form" onSubmit={submitBootstrap}>
                      <label htmlFor="bootstrap-code">一次性初始化码</label>
                      <input
                        id="bootstrap-code"
                        autoComplete="one-time-code"
                        autoFocus
                        maxLength={80}
                        onChange={(event) => setBootstrapCode(event.target.value)}
                        placeholder="XXXX-XXXX-XXXX-XXXX"
                        required
                        spellCheck={false}
                        value={bootstrapCode}
                      />
                      <button className="button button-primary" disabled={busy} type="submit">
                        {busy ? <LoaderCircle className="spin" size={18} /> : <ArrowRight size={18} />}
                        验证并继续
                      </button>
                    </form>
                  </section>
                )}

                {!status.recovery.required && status.state === "security_policy_required" && (
                  <section aria-labelledby="policy-title">
                    <div className="section-icon"><ShieldCheck aria-hidden="true" size={22} /></div>
                    <p className="eyebrow">步骤 2 / 3</p>
                    <h1 id="policy-title">确认安全与出境策略</h1>
                    <p className="section-summary">外部模型仅允许连接明确批准的 HTTPS 主机。</p>
                    <form className="setup-form" onSubmit={submitPolicy}>
                      <label htmlFor="provider-host">允许的模型服务主机</label>
                      <input
                        id="provider-host"
                        onChange={(event) => setProviderHost(event.target.value)}
                        required
                        spellCheck={false}
                        value={providerHost}
                      />
                      <div className="policy-list">
                        <div><CheckCircle2 size={17} /><span>不发送 SQL 字面量与凭据</span></div>
                        <div><CheckCircle2 size={17} /><span>不下载本地模型权重</span></div>
                        <div><CheckCircle2 size={17} /><span>禁止重定向与未批准主机</span></div>
                      </div>
                      <button className="button button-primary" disabled={busy} type="submit">
                        {busy ? <LoaderCircle className="spin" size={18} /> : <ShieldCheck size={18} />}
                        提交策略
                      </button>
                    </form>
                  </section>
                )}

                {!status.recovery.required && status.state === "model_required" && (
                  <section aria-labelledby="model-title">
                    <div className="section-icon"><Cloud aria-hidden="true" size={22} /></div>
                    <p className="eyebrow">步骤 3 / 3</p>
                    <h1 id="model-title">连接外部模型</h1>
                    <p className="section-summary">连通测试有严格超时，密钥不会写入日志。</p>
                    <form className="setup-form model-form" onSubmit={probeProvider}>
                      <label htmlFor="provider-url">OpenAI 兼容地址</label>
                      <input
                        id="provider-url"
                        onChange={(event) => setProviderUrl(event.target.value)}
                        required
                        spellCheck={false}
                        type="url"
                        value={providerUrl}
                      />
                      <label htmlFor="model-id">模型 ID</label>
                      <input
                        id="model-id"
                        onChange={(event) => setModel(event.target.value)}
                        placeholder="输入服务端返回的模型 ID"
                        required
                        spellCheck={false}
                        value={model}
                      />
                      <label htmlFor="api-key">API Key</label>
                      <input
                        id="api-key"
                        autoComplete="off"
                        onChange={(event) => setApiKey(event.target.value)}
                        required
                        type="password"
                        value={apiKey}
                      />
                      {providerVerified ? (
                        <div className="verified-row" role="status">
                          <CheckCircle2 aria-hidden="true" size={18} />
                          模型服务已验证
                        </div>
                      ) : (
                        <button className="button button-secondary" disabled={busy} type="submit">
                          {busy ? <LoaderCircle className="spin" size={18} /> : <Activity size={18} />}
                          测试连接
                        </button>
                      )}
                    </form>
                    <div className="completion-actions">
                      <button
                        className="button button-primary"
                        disabled={!providerVerified || busy}
                        onClick={() => finalize("external")}
                        type="button"
                      >
                        <ArrowRight size={18} />
                        启用外部模型
                      </button>
                      <button
                        className="button button-quiet"
                        disabled={busy}
                        onClick={() => finalize("rules")}
                        type="button"
                      >
                        使用规则模式
                      </button>
                    </div>
                  </section>
                )}

                {status.state === "ready" && (
                  <section aria-labelledby="ready-title">
                    <div className="section-icon section-icon-success">
                      <Check aria-hidden="true" size={22} />
                    </div>
                    <p className="eyebrow">初始化完成</p>
                    <h1 id="ready-title">诊断工作台已就绪</h1>
                    <p className="section-summary">
                      当前模式：{status.model_mode === "external" ? "外部模型" : "本地规则"}
                    </p>
                    <div className="ready-band">
                      <Activity aria-hidden="true" size={20} />
                      <span>运行状态正常</span>
                    </div>
                  </section>
                )}

                {status.state !== "ready" && <LocalModeStatus />}
              </>
            )}
          </div>
        </main>
      </div>
    </div>
  );
}

function messageFor(error: unknown): string {
  if (error instanceof ApiClientError) {
    return error.message;
  }
  return "无法连接本地服务，请确认容器仍在运行。";
}
