/**
 * HTTP client for the agent-identity service API.
 *
 * Uses the Fetch API (available natively in Node 18+, browsers, and Deno).
 * No external dependencies required.
 *
 * @example
 * ```ts
 * import { createAgentIdentityClient } from "@aumos/agent-identity";
 *
 * const client = createAgentIdentityClient({ baseUrl: "http://localhost:8070" });
 *
 * const identity = await client.getIdentity("my-agent");
 * if (identity.ok) {
 *   console.log("Organization:", identity.data.organization);
 * }
 *
 * const trust = await client.getTrustScore("my-agent");
 * if (trust.ok) {
 *   console.log("Composite trust:", trust.data.composite, "Level:", trust.data.level);
 * }
 * ```
 */

import type {
  AgentIdentity,
  ApiError,
  ApiResult,
  BehaviorValidation,
  Certificate,
  CreateIdentityRequest,
  DIDDocument,
  IssueCertificateRequest,
  TrustScore,
  VerifyRequest,
} from "./types.js";

// ---------------------------------------------------------------------------
// Client configuration
// ---------------------------------------------------------------------------

/** Configuration options for the AgentIdentityClient. */
export interface AgentIdentityClientConfig {
  /** Base URL of the agent-identity server (e.g. "http://localhost:8070"). */
  readonly baseUrl: string;
  /** Optional request timeout in milliseconds (default: 30000). */
  readonly timeoutMs?: number;
  /** Optional extra HTTP headers sent with every request. */
  readonly headers?: Readonly<Record<string, string>>;
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

async function fetchJson<T>(
  url: string,
  init: RequestInit,
  timeoutMs: number,
): Promise<ApiResult<T>> {
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), timeoutMs);

  try {
    const response = await fetch(url, { ...init, signal: controller.signal });
    clearTimeout(timeoutId);

    const body = await response.json() as unknown;

    if (!response.ok) {
      const errorBody = body as Partial<ApiError>;
      return {
        ok: false,
        error: {
          error: errorBody.error ?? "Unknown error",
          detail: errorBody.detail ?? "",
        },
        status: response.status,
      };
    }

    return { ok: true, data: body as T };
  } catch (err: unknown) {
    clearTimeout(timeoutId);
    const message = err instanceof Error ? err.message : String(err);
    return {
      ok: false,
      error: { error: "Network error", detail: message },
      status: 0,
    };
  }
}

function buildHeaders(
  extraHeaders: Readonly<Record<string, string>> | undefined,
): Record<string, string> {
  return {
    "Content-Type": "application/json",
    Accept: "application/json",
    ...extraHeaders,
  };
}

// ---------------------------------------------------------------------------
// Client interface
// ---------------------------------------------------------------------------

/** Typed HTTP client for the agent-identity service. */
export interface AgentIdentityClient {
  /**
   * Retrieve the full identity record for a registered agent.
   *
   * @param agentId - The unique agent identifier.
   * @returns The AgentIdentity record if found.
   */
  getIdentity(agentId: string): Promise<ApiResult<AgentIdentity>>;

  /**
   * Compute and retrieve the multi-dimensional trust score for an agent.
   *
   * Returns a TrustScore with per-dimension scores (competence, reliability,
   * integrity), a weighted composite score, and a derived TrustLevel.
   *
   * @param agentId - The unique agent identifier.
   * @returns The TrustScore with composite and per-dimension scores.
   */
  getTrustScore(agentId: string): Promise<ApiResult<TrustScore>>;

  /**
   * Verify an agent's identity and validate claimed capabilities.
   *
   * @param request - Verification request including agent_id and claimed capabilities.
   * @returns BehaviorValidation result with verified flag and missing capabilities.
   */
  validateBehavior(request: VerifyRequest): Promise<ApiResult<BehaviorValidation>>;

  /**
   * Issue a new X.509 certificate for a registered agent.
   *
   * The certificate encodes the agent's identity, capabilities, trust level,
   * and organizational affiliation using SAN URI extensions.
   *
   * @param request - Certificate issuance request including agent_id and validity.
   * @returns The issued Certificate with PEM-encoded cert and serial number.
   */
  issueCertificate(request: IssueCertificateRequest): Promise<ApiResult<Certificate>>;

  /**
   * Register a new agent identity in the registry.
   *
   * @param request - Identity creation payload with agent_id, display_name, and org.
   * @returns The newly created AgentIdentity record.
   */
  verifyIdentity(request: CreateIdentityRequest): Promise<ApiResult<AgentIdentity>>;

  /**
   * Resolve the W3C DID document for an agent by its DID string.
   *
   * The did:agent method format is: did:agent:<org>:<name>
   *
   * @param did - The fully-qualified DID string (e.g. "did:agent:acme:invoicer").
   * @returns The resolved DIDDocument conforming to W3C DID Core.
   */
  resolveDID(did: string): Promise<ApiResult<DIDDocument>>;
}

// ---------------------------------------------------------------------------
// Client factory
// ---------------------------------------------------------------------------

/**
 * Create a typed HTTP client for the agent-identity service.
 *
 * @param config - Client configuration including base URL.
 * @returns An AgentIdentityClient instance.
 */
export function createAgentIdentityClient(
  config: AgentIdentityClientConfig,
): AgentIdentityClient {
  const { baseUrl, timeoutMs = 30_000, headers: extraHeaders } = config;
  const baseHeaders = buildHeaders(extraHeaders);

  return {
    async getIdentity(agentId: string): Promise<ApiResult<AgentIdentity>> {
      return fetchJson<AgentIdentity>(
        `${baseUrl}/identities/${encodeURIComponent(agentId)}`,
        { method: "GET", headers: baseHeaders },
        timeoutMs,
      );
    },

    async getTrustScore(agentId: string): Promise<ApiResult<TrustScore>> {
      return fetchJson<TrustScore>(
        `${baseUrl}/trust/${encodeURIComponent(agentId)}`,
        { method: "GET", headers: baseHeaders },
        timeoutMs,
      );
    },

    async validateBehavior(
      request: VerifyRequest,
    ): Promise<ApiResult<BehaviorValidation>> {
      return fetchJson<BehaviorValidation>(
        `${baseUrl}/verify`,
        {
          method: "POST",
          headers: baseHeaders,
          body: JSON.stringify(request),
        },
        timeoutMs,
      );
    },

    async issueCertificate(
      request: IssueCertificateRequest,
    ): Promise<ApiResult<Certificate>> {
      return fetchJson<Certificate>(
        `${baseUrl}/certificates`,
        {
          method: "POST",
          headers: baseHeaders,
          body: JSON.stringify(request),
        },
        timeoutMs,
      );
    },

    async verifyIdentity(
      request: CreateIdentityRequest,
    ): Promise<ApiResult<AgentIdentity>> {
      return fetchJson<AgentIdentity>(
        `${baseUrl}/identities`,
        {
          method: "POST",
          headers: baseHeaders,
          body: JSON.stringify(request),
        },
        timeoutMs,
      );
    },

    async resolveDID(did: string): Promise<ApiResult<DIDDocument>> {
      return fetchJson<DIDDocument>(
        `${baseUrl}/did/${encodeURIComponent(did)}`,
        { method: "GET", headers: baseHeaders },
        timeoutMs,
      );
    },
  };
}

