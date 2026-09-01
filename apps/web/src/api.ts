export type SetupStage =
  | "bootstrap_required"
  | "security_policy_required"
  | "model_required"
  | "ready"
  | "model_recovery_required";

export interface LocalModelStatus {
  available: boolean;
  verified: boolean;
  code: string;
  message: string;
}

export interface SetupStatus {
  state: SetupStage;
  initialized: boolean;
  bootstrap_hash_persisted: boolean;
  model_mode: "external" | "rules" | null;
  csrf_token: string | null;
  recovery: {
    required: boolean;
    action: "bootstrap-reissue" | null;
    reason: "bootstrap_expired" | "attempt_limit_reached" | "setup_session_missing" | null;
  };
  external_model: {
    credential_available: boolean;
    egress_enabled: boolean;
  };
  local_model: LocalModelStatus;
}

export interface OwnerSession {
  authenticated: boolean;
  csrf_token: string | null;
}

export type ExplanationStatus = "pending" | "not_requested" | "applied" | "degraded";

export interface DiagnosisExplanation {
  status: ExplanationStatus;
  code: string | null;
  policy: string;
  payloadSchema: string | null;
  payloadDigest: string | null;
}

export interface DiagnosisJob {
  jobId: string;
  caseId: string;
  status: "in_progress" | "completed" | "failed";
  explanation: DiagnosisExplanation;
  error?: {
    code: string;
    retryable: boolean;
  };
}

export interface DiagnosisEvidence {
  evidenceId: string;
  kind: string;
  source: string;
  observedAt: string;
  collectedAt: string;
  freshness: string;
  coverage: number;
  sensitivity: string;
  integrityDigest: string;
  summary: string;
}

export interface DiagnosisHypothesis {
  hypothesisId: string;
  statement: string;
  confidence: number;
  supportingEvidenceIds: string[];
  contradictingEvidenceIds: string[];
  status: "candidate" | "supported" | "rejected";
}

export interface DiagnosisRecommendation {
  recommendationId: string;
  title: string;
  rationale: string;
  risk: "low" | "medium" | "high" | "critical";
  prerequisites: string[];
  validation: string[];
  rollback: string[];
  evidenceIds: string[];
  owner: {
    kind: string;
    id: string;
    displayName: string;
  };
  requiresHumanApproval: boolean;
}

export interface DiagnosisCase {
  schemaVersion: "diagnosis-case/v1";
  caseId: string;
  revision: number;
  sourceLayer: "sql";
  workflowState: "ready";
  outcome: "pending";
  inputFingerprint: string;
  createdAt: string;
  updatedAt: string;
  evidenceCompleteness: {
    score: number;
    classification: "insufficient" | "partial" | "sufficient";
    missing: string[];
  };
  evidence: DiagnosisEvidence[];
  hypotheses: DiagnosisHypothesis[];
  recommendations: DiagnosisRecommendation[];
  reviews: unknown[];
  feedback: unknown[];
  pinnedRevisions: {
    ruleSet: string;
    parser: string;
    policy: string;
    redaction: string;
    provider: string | null;
    model: string | null;
    modelArtifact: string | null;
    prompt: string | null;
  };
}

interface ErrorEnvelope {
  error?: {
    code?: string;
    message?: string;
  };
}

export class ApiClientError extends Error {
  readonly code: string;
  readonly status: number;

  constructor(code: string, message: string, status: number) {
    super(message);
    this.code = code;
    this.status = status;
  }
}

export async function apiRequest<T>(
  path: string,
  options: RequestInit = {},
  csrfToken?: string | null
): Promise<T> {
  const headers = new Headers(options.headers);
  if (options.body) {
    headers.set("Content-Type", "application/json");
  }
  if (csrfToken) {
    headers.set("X-CSRF-Token", csrfToken);
  }
  const response = await fetch(path, {
    ...options,
    headers,
    credentials: "same-origin"
  });
  const body = (await response.json()) as T & ErrorEnvelope;
  if (!response.ok) {
    throw new ApiClientError(
      body.error?.code ?? "REQUEST_FAILED",
      body.error?.message ?? "请求未完成，请重试。",
      response.status
    );
  }
  return body;
}
