import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

import { App } from "./App";

const bootstrapStatus = {
  state: "bootstrap_required",
  initialized: false,
  bootstrap_hash_persisted: true,
  model_mode: null,
  csrf_token: null,
  recovery: { required: false, action: null, reason: null },
  external_model: { credential_available: false, egress_enabled: false },
  local_model: {
    available: false,
    verified: false,
    code: "LOCAL_RUNTIME_UNAVAILABLE",
    message: "No qualified local model runtime is exposed to this service."
  }
};

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json" }
  });
}

describe("setup application", () => {
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("loads first-run status and submits the one-time initialization code", async () => {
    const fetchMock = vi
      .fn<typeof fetch>()
      .mockResolvedValueOnce(jsonResponse(bootstrapStatus))
      .mockResolvedValueOnce(
        jsonResponse({ state: "security_policy_required", csrf_token: "csrf-1" })
      );
    vi.stubGlobal("fetch", fetchMock);

    render(<App />);
    const codeInput = await screen.findByLabelText("一次性初始化码");
    fireEvent.change(codeInput, { target: { value: "ABCD-EFGH-JKLM-NPQR" } });
    fireEvent.click(screen.getByRole("button", { name: "验证并继续" }));

    await screen.findByRole("heading", { name: "确认安全与出境策略" });
    expect(fetchMock).toHaveBeenNthCalledWith(
      2,
      "/api/v1/setup/bootstrap",
      expect.objectContaining({
        method: "POST",
        body: JSON.stringify({ code: "ABCD-EFGH-JKLM-NPQR" })
      })
    );
  });

  it("shows local inference as unavailable instead of claiming GPU support", async () => {
    vi.stubGlobal("fetch", vi.fn<typeof fetch>().mockResolvedValue(jsonResponse(bootstrapStatus)));

    render(<App />);

    await waitFor(() => expect(screen.getByText("本地模型不可用")).toBeTruthy());
    expect(screen.getByText(/未检测或验证可用的本地模型运行时/)).toBeTruthy();
  });

  it("shows the executable local recovery action when setup cannot continue", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn<typeof fetch>().mockResolvedValue(
        jsonResponse({
          ...bootstrapStatus,
          recovery: {
            required: true,
            action: "bootstrap-reissue",
            reason: "bootstrap_expired"
          }
        })
      )
    );

    render(<App />);

    await screen.findByRole("heading", { name: "重新签发初始化码" });
    expect(screen.getByText("./launch.sh recover-setup")).toBeTruthy();
    expect(screen.queryByLabelText("一次性初始化码")).toBeNull();
  });

  it("keeps rule diagnosis available when only the external credential is degraded", async () => {
    const fetchMock = vi
      .fn<typeof fetch>()
      .mockResolvedValueOnce(
        jsonResponse({
          ...bootstrapStatus,
          state: "model_recovery_required",
          initialized: true,
          model_mode: "external",
          external_model: { credential_available: false }
        })
      )
      .mockResolvedValueOnce(
        jsonResponse({ authenticated: true, csrf_token: "owner-csrf" })
      );
    vi.stubGlobal("fetch", fetchMock);

    render(<App />);

    await screen.findByRole("heading", { name: "更新外部模型凭据" });
    expect(screen.getByText(/规则诊断仍可使用/)).toBeTruthy();
    expect(screen.queryByText(/诊断保持关闭/)).toBeNull();
  });

  it("creates the Owner during rules finalization and keeps the returned session", async () => {
    const fetchMock = vi
      .fn<typeof fetch>()
      .mockResolvedValueOnce(
        jsonResponse({
          ...bootstrapStatus,
          state: "model_required",
          csrf_token: "setup-csrf"
        })
      )
      .mockResolvedValueOnce(
        jsonResponse({
          state: "ready",
          model_mode: "rules",
          authenticated: true,
          owner_csrf_token: "owner-csrf"
        })
      );
    vi.stubGlobal("fetch", fetchMock);

    render(<App />);

    fireEvent.change(await screen.findByLabelText("Owner 密码"), {
      target: { value: "correct-horse-battery-staple" }
    });
    fireEvent.change(screen.getByLabelText("确认 Owner 密码"), {
      target: { value: "correct-horse-battery-staple" }
    });
    fireEvent.click(screen.getByRole("button", { name: "使用规则模式" }));

    await screen.findByRole("heading", { name: "诊断工作台已就绪" });
    const [, finalizeOptions] = fetchMock.mock.calls[1];
    expect(finalizeOptions?.body).toBe(
      JSON.stringify({
        mode: "rules",
        owner_password: "correct-horse-battery-staple"
      })
    );
    expect(new Headers(finalizeOptions?.headers).get("X-CSRF-Token")).toBe("setup-csrf");
  });

  it("restores a rules-only policy without exposing the external provider form", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn<typeof fetch>().mockResolvedValue(
        jsonResponse({
          ...bootstrapStatus,
          state: "model_required",
          csrf_token: "setup-csrf",
          external_model: {
            credential_available: false,
            egress_enabled: false
          }
        })
      )
    );

    render(<App />);

    await screen.findByRole("heading", { name: "连接外部模型" });
    expect(screen.queryByLabelText("OpenAI 兼容地址")).toBeNull();
    fireEvent.change(screen.getByLabelText("Owner 密码"), {
      target: { value: "correct-horse-battery-staple" }
    });
    fireEvent.change(screen.getByLabelText("确认 Owner 密码"), {
      target: { value: "correct-horse-battery-staple" }
    });
    expect(
      (screen.getByRole("button", { name: "使用规则模式" }) as HTMLButtonElement)
        .disabled
    ).toBe(false);
  });

  it("logs an Owner in after restart and revokes the session with CSRF", async () => {
    const readyStatus = {
      ...bootstrapStatus,
      state: "ready",
      initialized: true,
      model_mode: "rules",
      external_model: { credential_available: false }
    };
    const fetchMock = vi
      .fn<typeof fetch>()
      .mockResolvedValueOnce(jsonResponse(readyStatus))
      .mockResolvedValueOnce(
        jsonResponse({ authenticated: false, csrf_token: null })
      )
      .mockResolvedValueOnce(
        jsonResponse({ authenticated: true, csrf_token: "owner-csrf" })
      )
      .mockResolvedValueOnce(jsonResponse({ authenticated: false }));
    vi.stubGlobal("fetch", fetchMock);

    render(<App />);

    fireEvent.change(await screen.findByLabelText("Owner 密码"), {
      target: { value: "correct-horse-battery-staple" }
    });
    fireEvent.click(screen.getByRole("button", { name: "登录" }));
    await screen.findByRole("heading", { name: "诊断工作台已就绪" });

    fireEvent.click(screen.getByRole("button", { name: "退出 Owner 会话" }));
    await screen.findByRole("heading", { name: "登录诊断工作台" });
    const [, logoutOptions] = fetchMock.mock.calls[3];
    expect(new Headers(logoutOptions?.headers).get("X-CSRF-Token")).toBe("owner-csrf");
  });

  it("rotates a degraded external credential with the Owner CSRF token", async () => {
    const fetchMock = vi
      .fn<typeof fetch>()
      .mockResolvedValueOnce(
        jsonResponse({
          ...bootstrapStatus,
          state: "model_recovery_required",
          initialized: true,
          model_mode: "external",
          external_model: { credential_available: false }
        })
      )
      .mockResolvedValueOnce(
        jsonResponse({ authenticated: true, csrf_token: "owner-csrf" })
      )
      .mockResolvedValueOnce(
        jsonResponse({ model_mode: "external", credential_available: true })
      );
    vi.stubGlobal("fetch", fetchMock);

    render(<App />);

    fireEvent.change(await screen.findByLabelText("模型 ID"), {
      target: { value: "demo-model" }
    });
    fireEvent.change(screen.getByLabelText("API Key"), {
      target: { value: "provider-secret" }
    });
    fireEvent.click(screen.getByRole("button", { name: "验证并更新" }));

    await screen.findByRole("heading", { name: "诊断工作台已就绪" });
    const [, rotateOptions] = fetchMock.mock.calls[2];
    expect(rotateOptions?.method).toBe("PUT");
    expect(new Headers(rotateOptions?.headers).get("X-CSRF-Token")).toBe("owner-csrf");
  });
});
