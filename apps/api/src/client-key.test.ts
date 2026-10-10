import { describe, expect, it } from "vitest";
import { BlockList } from "node:net";
import { clientKey } from "./app.js";

const trusted = new BlockList();
trusted.addAddress("10.0.0.2");
trusted.addAddress("10.0.0.5");

describe("clientKey", () => {
  it("uses the socket address when no proxy is trusted", () => {
    expect(clientKey("6.6.6.6", "192.0.2.10", 0)).toBe("192.0.2.10");
  });

  it("takes the entry the outermost trusted proxy appended", () => {
    expect(clientKey("6.6.6.6, 203.0.113.7", "10.0.0.2", 1, trusted)).toBe(
      "203.0.113.7",
    );
    expect(clientKey("6.6.6.6, 203.0.113.7, 10.0.0.5", "10.0.0.2", 2, trusted)).toBe(
      "203.0.113.7",
    );
  });

  it("uses the socket address when the chain is shorter than the hop count", () => {
    expect(clientKey("203.0.113.7", "10.0.0.2", 2, trusted)).toBe("10.0.0.2");
    expect(clientKey("spoof", undefined, 2)).toBe("unknown");
  });

  it("falls back to the socket address when the header is missing or blank", () => {
    expect(clientKey(undefined, "10.0.0.2", 1, trusted)).toBe("10.0.0.2");
    expect(clientKey(" , ", "10.0.0.2", 1, trusted)).toBe("10.0.0.2");
  });

  it("returns a shared key when nothing identifies the caller", () => {
    expect(clientKey(undefined, undefined, 0)).toBe("unknown");
  });

  it("rejects padded headers when the actual path has fewer trusted proxies", () => {
    expect(clientKey("192.0.2.1, 192.0.2.2, 203.0.113.7", "10.0.0.2", 2, trusted)).toBe("10.0.0.2");
  });

  it("ignores headers from an untrusted socket peer", () => {
    expect(clientKey("192.0.2.1", "203.0.113.7", 1, trusted)).toBe("203.0.113.7");
    expect(clientKey("192.0.2.1", "10.0.0.2", 1)).toBe("10.0.0.2");
  });

  it("matches IPv4-mapped IPv6 proxy peers", () => {
    expect(clientKey("203.0.113.7", "::ffff:10.0.0.2", 1, trusted)).toBe("203.0.113.7");
  });

  it("fails closed for a malformed selected client address", () => {
    expect(clientKey("not-an-ip", "10.0.0.2", 1, trusted)).toBe("10.0.0.2");
  });
});
