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

interface ErrorEnvelope {
  error?: {
    code?: string;
    message?: string;
  };
}

export class ApiClientError extends Error {
  readonly code: string;

  constructor(code: string, message: string) {
    super(message);
    this.code = code;
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
      body.error?.message ?? "请求未完成，请重试。"
    );
  }
  return body;
}
