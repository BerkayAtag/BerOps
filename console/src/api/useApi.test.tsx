import { act, renderHook, waitFor } from "@testing-library/react";
import { afterEach, expect, it, vi } from "vitest";
import { useApi } from "./useApi";

afterEach(() => vi.unstubAllGlobals());

it("makine değişirken önceki makinenin verisini göstermez", async () => {
  let complete!: (response: Response) => void;
  vi.stubGlobal(
    "fetch",
    vi.fn((path: string) =>
      path === "/a"
        ? Promise.resolve(new Response(JSON.stringify({ name: "A" })))
        : new Promise<Response>((resolve) => {
            complete = resolve;
          }),
    ),
  );
  const { result, rerender } = renderHook(({ path }) => useApi<{ name: string }>(path), {
    initialProps: { path: "/a" as string | null },
  });
  await waitFor(() => expect(result.current[0]).toEqual({ status: "ok", data: { name: "A" } }));
  rerender({ path: "/b" });
  expect(result.current[0]).toEqual({ status: "loading" });
  await act(async () => complete(new Response(JSON.stringify({ name: "B" }))));
  expect(result.current[0]).toEqual({ status: "ok", data: { name: "B" } });
  rerender({ path: null });
  expect(result.current[0]).toEqual({ status: "loading" });
});

it("eski isteğin geç gelen yanıtını yeni kayda uygulamaz", async () => {
  let complete!: (response: Response) => void;
  vi.stubGlobal(
    "fetch",
    vi.fn((path: string) =>
      path === "/a"
        ? new Promise<Response>((resolve) => {
            complete = resolve;
          })
        : Promise.resolve(new Response(JSON.stringify("B"))),
    ),
  );
  const { result, rerender } = renderHook(({ path }) => useApi<string>(path), {
    initialProps: { path: "/a" },
  });
  rerender({ path: "/b" });
  await waitFor(() => expect(result.current[0]).toEqual({ status: "ok", data: "B" }));
  await act(async () => complete(new Response(JSON.stringify("A"))));
  expect(result.current[0]).toEqual({ status: "ok", data: "B" });
});
