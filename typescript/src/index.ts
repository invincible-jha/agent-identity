/**
 * @aumos/agent-identity
 *
 * TypeScript client for the AumOS agent-identity service.
 * Provides HTTP client and type definitions for DID resolution,
 * trust scoring, behavioral validation, and certificate issuance.
 */

// Client and configuration
export type { AgentIdentityClient, AgentIdentityClientConfig } from "./client.js";
export { createAgentIdentityClient } from "./client.js";

// Core types
export type {
  TrustDimension,
  TrustLevel,
  TrustScore,
  AgentIdentity,
  CreateIdentityRequest,
  VerifyRequest,
  BehaviorValidation,
  Certificate,
  IssueCertificateRequest,
  VerificationMethod,
  ServiceEndpoint,
  DIDDocument,
  ApiError,
  ApiResult,
} from "./types.js";
