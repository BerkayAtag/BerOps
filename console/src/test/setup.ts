import "@testing-library/jest-dom/vitest";
import { afterEach } from "vitest";
import { cleanup } from "@testing-library/react";

// Node 25+ kendi deneysel localStorage global'ini tanımlar ve bu, jsdom'un Storage
// uygulamasını gölgeler (getItem tanımsız olur). Bu durumda bellek içi bir Storage kullanılır.
if (typeof globalThis.localStorage?.getItem !== "function") {
  class MemoryStorage implements Storage {
    private data = new Map<string, string>();
    get length() {
      return this.data.size;
    }
    clear() {
      this.data.clear();
    }
    getItem(key: string) {
      return this.data.get(key) ?? null;
    }
    key(i: number) {
      return [...this.data.keys()][i] ?? null;
    }
    removeItem(key: string) {
      this.data.delete(key);
    }
    setItem(key: string, value: string) {
      this.data.set(key, String(value));
    }
  }
  Object.defineProperty(globalThis, "localStorage", { value: new MemoryStorage(), configurable: true });
}

afterEach(() => {
  cleanup();
  localStorage.clear();
});
