import { Check, FileSearch, LockKeyhole } from "lucide-react";
import { ReactNode } from "react";

import { SetupStage } from "./api";

const SETUP_STEPS: Array<{ stage: SetupStage; label: string }> = [
  { stage: "bootstrap_required", label: "验证身份" },
  { stage: "security_policy_required", label: "安全策略" },
  { stage: "model_required", label: "模型连接" },
  { stage: "ready", label: "完成" }
];

interface PhaseShellProps {
  activeStage: SetupStage;
  children: ReactNode;
  initialized: boolean;
  phaseKnown: boolean;
  workbench: boolean;
}

export function PhaseShell({
  activeStage,
  children,
  initialized,
  phaseKnown,
  workbench
}: PhaseShellProps) {
  if (!phaseKnown) {
    return (
      <div className="workspace workspace-loading">
        <main className="setup-main">
          <div className="setup-content">{children}</div>
        </main>
      </div>
    );
  }
  if (initialized) {
    return <DailyShell workbench={workbench}>{children}</DailyShell>;
  }
  return <SetupShell activeStage={activeStage}>{children}</SetupShell>;
}

function SetupShell({
  activeStage,
  children
}: Pick<PhaseShellProps, "activeStage" | "children">) {
  const activeIndex = stageIndex(activeStage);

  return (
    <div className="workspace">
      <aside className="step-rail">
        <p className="rail-title">初始化</p>
        <nav aria-label="安装与初始化导航">
          <ol>
            {SETUP_STEPS.map((step, index) => {
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
        </nav>
        <div className="rail-boundary">
          <LockKeyhole aria-hidden="true" size={17} />
          <span>默认仅监听本机</span>
        </div>
      </aside>
      <main className="setup-main">
        <div className="setup-content">{children}</div>
      </main>
    </div>
  );
}

function DailyShell({
  children,
  workbench
}: Pick<PhaseShellProps, "children" | "workbench">) {
  return (
    <div className="workspace workspace-diagnosis">
      <aside className="diagnosis-rail">
        <p className="rail-title">工作台</p>
        <nav aria-label="日常诊断导航">
          <ul>
            <li>
              <span aria-current={workbench ? "page" : undefined} className="diagnosis-nav-active">
                <FileSearch aria-hidden="true" size={18} />
                SQL 诊断
              </span>
            </li>
          </ul>
        </nav>
        <div className="diagnosis-boundary">
          <LockKeyhole aria-hidden="true" size={17} />
          <div>
            <strong>Owner 会话</strong>
            <span>仅监听本机</span>
          </div>
        </div>
      </aside>
      <main className={workbench ? "diagnosis-main" : "setup-main"}>
        <div className={workbench ? "diagnosis-content" : "setup-content"}>{children}</div>
      </main>
    </div>
  );
}

function stageIndex(stage: SetupStage): number {
  if (stage === "model_recovery_required") {
    return SETUP_STEPS.length - 1;
  }
  return SETUP_STEPS.findIndex((step) => step.stage === stage);
}
