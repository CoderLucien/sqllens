import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

import { DiagnosisWorkspace } from "./DiagnosisWorkspace";

const diagnosisCase = {
  schemaVersion: "diagnosis-case/v1",
  caseId: "case_1234567890abcdef",
  revision: 1,
  sourceLayer: "sql",
  workflowState: "ready",
  outcome: "pending",
  inputFingerprint: `sha256:${"a".repeat(64)}`,
  createdAt: "2026-09-01T00:00:00Z",
  updatedAt: "2026-09-01T00:00:00Z",
  evidenceCompleteness: {
    score: 0.2,
    classification: "insufficient",
    missing: ["tidb_version", "schema", "ordinary_plan"]
  },
  evidence: [
    {
      evidenceId: "ev_1234567890abcdef",
      kind: "sql_structure",
      source: "sqlglot/mysql@30.17.0",
      observedAt: "2026-09-01T00:00:00Z",
      collectedAt: "2026-09-01T00:00:00Z",
      freshness: "fresh",
      coverage: 0.2,
      sensitivity: "metadata",
      integrityDigest: `sha256:${"b".repeat(64)}`,
      summary: "Parsed one read-only MySQL query structure with one table reference."
    }
  ],
  hypotheses: [
    {
      hypothesisId: "hyp_1234567890abcdef",
      statement: "The SQL structure alone cannot establish a TiDB execution bottleneck.",
      confidence: 0.2,
      supportingEvidenceIds: ["ev_1234567890abcdef"],
      contradictingEvidenceIds: [],
      status: "candidate"
    }
  ],
  recommendations: [
    {
      recommendationId: "rec_1234567890abcdef",
      title: "Collect read-only TiDB context",
      rationale: "SQL structure alone cannot justify a production change.",
      risk: "low",
      prerequisites: ["Obtain an approved read-only TiDB metadata connection"],
      validation: ["Collect TiDB version, schema metadata, and an ordinary plan"],
      rollback: ["Disconnect the read-only source and discard collected metadata"],
      evidenceIds: ["ev_1234567890abcdef"],
      owner: {
        kind: "role",
        id: "dba",
        displayName: "Database administrator"
      },
      requiresHumanApproval: true
    }
  ],
  reviews: [],
  feedback: [],
  pinnedRevisions: {
    ruleSet: "sql-rules/v1",
    parser: "sqlglot/mysql@30.17.0",
    policy: "policy/v1",
    redaction: "sql-structure/v1",
    provider: null,
    model: null,
    modelArtifact: null,
    prompt: null
  }
};

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json" }
  });
}

function completedJob(status: "not_requested" | "applied" | "degraded", code: string | null) {
  return {
    jobId: "job_1234567890abcdef",
    caseId: diagnosisCase.caseId,
    status: "completed",
    explanation: {
      status,
      code,
      policy: status === "not_requested" ? "rules-only/v1" : "model-egress/metadata-only-v1",
      payloadSchema: status === "not_requested" ? null : "sqllens-model-ranking-request/v1",
      payloadDigest: status === "not_requested" ? null : `sha256:${"c".repeat(64)}`
    }
  };
}

describe("diagnosis workspace", () => {
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("creates and renders an evidence-first Diagnosis Case", async () => {
    const fetchMock = vi
      .fn<typeof fetch>()
      .mockResolvedValueOnce(jsonResponse(completedJob("not_requested", null), 202))
      .mockResolvedValueOnce(jsonResponse(diagnosisCase));
    vi.stubGlobal("fetch", fetchMock);

    render(<DiagnosisWorkspace csrfToken="owner-csrf" modelMode="rules" />);

    fireEvent.change(screen.getByRole("textbox", { name: "SQL" }), {
      target: { value: "SELECT * FROM orders WHERE state = 'open'" }
    });
    fireEvent.click(screen.getByRole("button", { name: "生成诊断案例" }));

    await screen.findByRole("heading", { name: "证据完整度" });
    expect(screen.getByText("证据不足")).toBeTruthy();
    expect(screen.getByText(/cannot establish a TiDB execution bottleneck/)).toBeTruthy();
    expect(screen.getByText("验证")).toBeTruthy();
    expect(screen.getByText("回滚")).toBeTruthy();
    expect(screen.getAllByText("ev_1234567890abcdef")).toHaveLength(2);

    expect(fetchMock).toHaveBeenNthCalledWith(
      1,
      "/api/v1/cases/sql",
      expect.objectContaining({
        method: "POST",
        body: JSON.stringify({ sql: "SELECT * FROM orders WHERE state = 'open'" })
      })
    );
    const [, createOptions] = fetchMock.mock.calls[0];
    const createHeaders = new Headers(createOptions?.headers);
    expect(createHeaders.get("X-CSRF-Token")).toBe("owner-csrf");
    expect(createHeaders.get("Idempotency-Key")).toMatch(/^web-/);
    expect(fetchMock).toHaveBeenNthCalledWith(
      2,
      `/api/v1/cases/${diagnosisCase.caseId}`,
      expect.any(Object)
    );
  });

  it("keeps the deterministic Case visible when model ranking degrades", async () => {
    const fetchMock = vi
      .fn<typeof fetch>()
      .mockResolvedValueOnce(
        jsonResponse(completedJob("degraded", "MODEL_RESPONSE_TIMEOUT"), 202)
      )
      .mockResolvedValueOnce(jsonResponse(diagnosisCase));
    vi.stubGlobal("fetch", fetchMock);

    render(<DiagnosisWorkspace csrfToken="owner-csrf" modelMode="external" />);
    fireEvent.change(screen.getByRole("textbox", { name: "SQL" }), {
      target: { value: "SELECT 1" }
    });
    fireEvent.click(screen.getByRole("button", { name: "生成诊断案例" }));

    await screen.findByText("规则结果 · 模型不可用");
    expect(screen.getByText("MODEL_RESPONSE_TIMEOUT")).toBeTruthy();
    expect(screen.getByText(/cannot establish a TiDB execution bottleneck/)).toBeTruthy();
  });

  it("blocks SQL whose UTF-8 representation exceeds 64 KiB", () => {
    const fetchMock = vi.fn<typeof fetch>();
    vi.stubGlobal("fetch", fetchMock);

    render(<DiagnosisWorkspace csrfToken="owner-csrf" modelMode="rules" />);
    fireEvent.change(screen.getByRole("textbox", { name: "SQL" }), {
      target: { value: "数".repeat(21_846) }
    });

    expect(screen.getByText("输入超过 64 KiB 限制")).toBeTruthy();
    expect(
      (screen.getByRole("button", { name: "生成诊断案例" }) as HTMLButtonElement).disabled
    ).toBe(true);
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("shows a bounded API error without discarding the submitted SQL", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn<typeof fetch>().mockResolvedValue(
        jsonResponse(
          { error: { code: "SQL_INPUT_NOT_READ_ONLY", message: "Only read-only SQL is accepted." } },
          422
        )
      )
    );

    render(<DiagnosisWorkspace csrfToken="owner-csrf" modelMode="rules" />);
    const input = screen.getByRole("textbox", { name: "SQL" }) as HTMLTextAreaElement;
    fireEvent.change(input, { target: { value: "DELETE FROM orders" } });
    fireEvent.click(screen.getByRole("button", { name: "生成诊断案例" }));

    await waitFor(() => {
      expect(screen.getByRole("alert").textContent).toContain("Only read-only SQL is accepted.");
    });
    expect(input.value).toBe("DELETE FROM orders");
  });

  it("returns an expired Owner session to the login shell", async () => {
    const onAuthRequired = vi.fn();
    vi.stubGlobal(
      "fetch",
      vi.fn<typeof fetch>().mockResolvedValue(
        jsonResponse(
          { error: { code: "AUTH_REQUIRED", message: "Owner authentication is required." } },
          401
        )
      )
    );

    render(
      <DiagnosisWorkspace
        csrfToken="expired-csrf"
        modelMode="rules"
        onAuthRequired={onAuthRequired}
      />
    );
    fireEvent.change(screen.getByRole("textbox", { name: "SQL" }), {
      target: { value: "SELECT 1" }
    });
    fireEvent.click(screen.getByRole("button", { name: "生成诊断案例" }));

    await waitFor(() => expect(onAuthRequired).toHaveBeenCalledOnce());
  });
});
