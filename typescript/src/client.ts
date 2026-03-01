/**
 * HTTP client for the agent-identity service API.
 *
 * Delegates all HTTP transport to `@aumos/sdk-core` which provides
 * automatic retry with exponential back-off, timeout management via
 * `AbortSignal.timeout`, interceptor support, and a typed error hierarchy.
 *
 * The public-facing `ApiResult<T>` envelope is preserved for full
 * backward compatibility with existing callers.
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
 * ```
 */

import {
  createHttpClient,
  HttpError,
  NetworkError,
  TimeoutError,
  AumosError,
  type HttpClient,
} from "@aumos/sdk-core";

import type {
  AgentIdentity,
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
// Internal adapter
// ---------------------------------------------------------------------------

async function callApi<T>(
  operation: () => Promise<{ readonly data: T; readonly status: number }>,
): Promise<ApiResult<T>> {
  try {
    const response = await operation();
    return { ok: true, data: response.data };
  } catch (error: unknown) {
    if (error instanceof HttpError) {
      return {
        ok: false,
        error: { error: error.message, detail: String(error.body ?? "") },
        status: error.statusCode,
      };
    }
    if (error instanceof TimeoutError) {
      return {
        ok: false,
        error: { error: "Request timed out", detail: error.message },
        status: 0,
      };
    }
    if (error instanceof NetworkError) {
      return {
        ok: false,
        error: { error: "Network error", detail: error.message },
        status: 0,
      };
    }
    if (error instanceof AumosError) {
      return {
        ok: false,
        error: { error: error.code, detail: error.message },
        status: error.statusCode ?? 0,
      };
    }
    const message = error instanceof Error ? error.message : String(error);
    return {
      ok: false,
      error: { error: "Unexpected error", detail: message },
      status: 0,
    };
  }
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
  const http: HttpClient = createHttpClient({
    baseUrl: config.baseUrl,
    timeout: config.timeoutMs ?? 30_000,
    defaultHeaders: config.headers,
  });

  return {
    getIdentity(agentId: string): Promise<ApiResult<AgentIdentity>> {
      return callApi(() =>
        http.get<AgentIdentity>(`/identities/${encodeURIComponent(agentId)}`),
      );
    },

    getTrustScore(agentId: string): Promise<ApiResult<TrustScore>> {
      return callApi(() =>
        http.get<TrustScore>(`/trust/${encodeURIComponent(agentId)}`),
      );
    },

    validateBehavior(request: VerifyRequest): Promise<ApiResult<BehaviorValidation>> {
      return callApi(() => http.post<BehaviorValidation>("/verify", request));
    },

    issueCertificate(request: IssueCertificateRequest): Promise<ApiResult<Certificate>> {
      return callApi(() => http.post<Certificate>("/certificates", request));
    },

    verifyIdentity(request: CreateIdentityRequest): Promise<ApiResult<AgentIdentity>> {
      return callApi(() => http.post<AgentIdentity>("/identities", request));
    },

    resolveDID(did: string): Promise<ApiResult<DIDDocument>> {
      return callApi(() =>
        http.get<DIDDocument>(`/did/${encodeURIComponent(did)}`),
      );
    },
  };
}
