/**
 * TypeScript interfaces for the agent-identity service.
 *
 * Mirrors the Pydantic models defined in:
 *   agent_identity.server.models
 *   agent_identity.trust.scorer
 *   agent_identity.did.document
 *   agent_identity.certificates.agent_cert
 *
 * All interfaces use readonly fields to match Python's frozen Pydantic models.
 */

// ---------------------------------------------------------------------------
// Trust dimensions and levels
// ---------------------------------------------------------------------------

/**
 * The three axes of agent trust measurement.
 * Maps to TrustDimension enum in Python.
 */
export type TrustDimension = "competence" | "reliability" | "integrity";

/**
 * Human-readable trust level derived from a composite trust score.
 * Maps to TrustLevel enum in Python.
 */
export type TrustLevel = "UNTRUSTED" | "LOW" | "MEDIUM" | "HIGH" | "VERIFIED";

// ---------------------------------------------------------------------------
// TrustScore
// ---------------------------------------------------------------------------

/**
 * Computed trust score for a single agent at a point in time.
 * Maps to TrustScore dataclass in agent_identity.trust.scorer.
 */
export interface TrustScore {
  /** The agent whose trust is being measured. */
  readonly agent_id: string;
  /** Per-dimension scores keyed by TrustDimension (0–100 each). */
  readonly dimensions: Readonly<Record<TrustDimension, number>>;
  /** Weighted composite score derived from dimension scores. */
  readonly composite: number;
  /** TrustLevel derived from the composite score. */
  readonly level: TrustLevel;
  /** ISO-8601 UTC timestamp when this score was computed. */
  readonly timestamp: string;
}

// ---------------------------------------------------------------------------
// AgentIdentity (IdentityResponse)
// ---------------------------------------------------------------------------

/**
 * Full identity record for a registered agent.
 * Maps to IdentityResponse in agent_identity.server.models.
 */
export interface AgentIdentity {
  /** Unique agent identifier. */
  readonly agent_id: string;
  /** Human-readable display name. */
  readonly display_name: string;
  /** Owning organization or deployment namespace. */
  readonly organization: string;
  /** List of capability strings this agent is authorized to exercise. */
  readonly capabilities: readonly string[];
  /** Arbitrary key-value metadata attached to this identity. */
  readonly metadata: Readonly<Record<string, unknown>>;
  /** W3C DID string for this agent (empty string if not assigned). */
  readonly did: string;
  /** ISO-8601 UTC timestamp when the identity was first registered. */
  readonly registered_at: string;
  /** ISO-8601 UTC timestamp of the most recent update. */
  readonly updated_at: string;
  /** Whether this identity is currently active. */
  readonly active: boolean;
}

// ---------------------------------------------------------------------------
// CreateIdentityRequest
// ---------------------------------------------------------------------------

/**
 * Request payload for registering a new agent identity.
 * Maps to CreateIdentityRequest in agent_identity.server.models.
 */
export interface CreateIdentityRequest {
  /** Unique agent identifier. Must not contain spaces. */
  readonly agent_id: string;
  /** Human-readable display name. */
  readonly display_name: string;
  /** Owning organization. */
  readonly organization: string;
  /** Capability strings the agent is authorized to exercise. */
  readonly capabilities?: readonly string[];
  /** Arbitrary key-value metadata. */
  readonly metadata?: Readonly<Record<string, string>>;
  /** Optional W3C DID string in did:agent:<org>:<name> format. */
  readonly did?: string;
}

// ---------------------------------------------------------------------------
// VerifyRequest / VerifyResponse
// ---------------------------------------------------------------------------

/**
 * Request payload for verifying an agent's identity and capabilities.
 * Maps to VerifyRequest in agent_identity.server.models.
 */
export interface VerifyRequest {
  /** Agent identifier to verify. */
  readonly agent_id: string;
  /** Capabilities the caller claims this agent possesses. */
  readonly claimed_capabilities?: readonly string[];
  /** Arbitrary context key-value pairs for the verification request. */
  readonly context?: Readonly<Record<string, string>>;
}

/**
 * Result of an identity and capability verification check.
 * Maps to VerifyResponse in agent_identity.server.models.
 */
export interface BehaviorValidation {
  /** The agent identifier that was verified. */
  readonly agent_id: string;
  /** True when the agent is registered, active, and capabilities are valid. */
  readonly verified: boolean;
  /** Whether the agent record is currently active. */
  readonly active: boolean;
  /** Whether all claimed capabilities are present on the registered record. */
  readonly capabilities_valid: boolean;
  /** Capability strings from claimed_capabilities that are not registered. */
  readonly missing_capabilities: readonly string[];
  /** Optional composite trust score for this agent. */
  readonly trust_score: number | null;
  /** Human-readable description of the verification outcome. */
  readonly message: string;
}

// ---------------------------------------------------------------------------
// Certificate
// ---------------------------------------------------------------------------

/**
 * Serialized X.509 agent certificate returned by the issuance endpoint.
 * Maps to AgentCertificate dataclass in agent_identity.certificates.agent_cert.
 */
export interface Certificate {
  /** The agent this certificate was issued for. */
  readonly agent_id: string;
  /** Owning organization. */
  readonly organization: string;
  /** Capabilities baked into the certificate at issuance. */
  readonly capabilities: readonly string[];
  /** Trust level integer (0–4) encoded in the certificate. */
  readonly trust_level: number;
  /** PEM-encoded X.509 certificate (base64 string). */
  readonly cert_pem: string;
  /** Certificate serial number as a decimal string. */
  readonly serial_number: string;
  /** ISO-8601 UTC validity start. */
  readonly not_before: string;
  /** ISO-8601 UTC validity end. */
  readonly not_after: string;
}

// ---------------------------------------------------------------------------
// IssueCertificateRequest
// ---------------------------------------------------------------------------

/**
 * Request payload for issuing a new agent certificate.
 */
export interface IssueCertificateRequest {
  /** Agent identifier to issue the certificate for. */
  readonly agent_id: string;
  /** Number of days the certificate should remain valid (default 365). */
  readonly validity_days?: number;
}

// ---------------------------------------------------------------------------
// DIDDocument
// ---------------------------------------------------------------------------

/**
 * A verification method attached to a DID document.
 * Maps to VerificationMethod dataclass in agent_identity.did.document.
 */
export interface VerificationMethod {
  /** Verification method identifier (e.g. "did:agent:org:name#key-1"). */
  readonly id: string;
  /** Key type: "Ed25519VerificationKey2020" or "JsonWebKey2020". */
  readonly type: "Ed25519VerificationKey2020" | "JsonWebKey2020";
  /** DID that controls this key. */
  readonly controller: string;
  /** Public key encoded in multibase format. */
  readonly publicKeyMultibase: string;
}

/**
 * A service endpoint advertised in a DID document.
 * Maps to ServiceEndpoint dataclass in agent_identity.did.document.
 */
export interface ServiceEndpoint {
  /** Service identifier (e.g. "did:agent:org:name#messaging"). */
  readonly id: string;
  /** Service type string (e.g. "AgentMessaging", "LinkedDomains"). */
  readonly type: string;
  /** The URL or URI for this service. */
  readonly serviceEndpoint: string;
}

/**
 * A W3C DID Core compliant DID document for the did:agent method.
 * Maps to DIDDocument in agent_identity.did.document.
 *
 * DID format: did:agent:<org>:<name>
 */
export interface DIDDocument {
  /** JSON-LD context URIs. */
  readonly "@context": readonly string[];
  /** The DID subject identifier in did:agent:<org>:<name> format. */
  readonly id: string;
  /** DID(s) authorized to make changes to this document. */
  readonly controller: string | readonly string[];
  /** Cryptographic public keys associated with this DID. */
  readonly verificationMethod: readonly VerificationMethod[];
  /** Verification method IDs authorized for authentication. */
  readonly authentication: readonly string[];
  /** Verification method IDs authorized for assertions. */
  readonly assertionMethod: readonly string[];
  /** Service endpoints associated with this DID subject. */
  readonly service: readonly ServiceEndpoint[];
  /** ISO-8601 UTC timestamp when this document was first created. */
  readonly created: string;
  /** ISO-8601 UTC timestamp of the most recent update. */
  readonly updated: string;
}

// ---------------------------------------------------------------------------
// API result wrapper (shared pattern)
// ---------------------------------------------------------------------------

/** Standard error payload returned by the agent-identity API. */
export interface ApiError {
  readonly error: string;
  readonly detail: string;
}

/** Result type for all client operations. */
export type ApiResult<T> =
  | { readonly ok: true; readonly data: T }
  | { readonly ok: false; readonly error: ApiError; readonly status: number };
