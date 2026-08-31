import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

import { App } from "./App";

const bootstrapStatus = {
  state: "bootstrap_required",
  initialized: false,
  model_mode: null,
  csrf_token: null,
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
});
