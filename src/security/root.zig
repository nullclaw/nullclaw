//! Security module — encryption, policy enforcement, audit logging, pairing, sandboxing.
//!
//! Ported from ZeroClaw's Rust security module. Provides:
//! - SecurityPolicy: command allowlists, path validation, risk classification
//! - AuditEvent/AuditLogger: structured audit logging to JSON files
//! - PairingGuard: gateway authentication with one-time pairing codes
//! - SecretStore: ChaCha20-Poly1305 AEAD encryption for API keys on disk
//! - Sandbox: vtable interface for OS-level isolation backends
//! - ActionTracker/RateTracker: sliding-window rate limiting

pub const audit = @import("audit.zig");
pub const policy = @import("policy.zig");
pub const pairing = @import("pairing.zig");
pub const secrets = @import("secrets.zig");
pub const sandbox = @import("sandbox.zig");
pub const tracker = @import("tracker.zig");
pub const landlock = @import("landlock.zig");
pub const firejail = @import("firejail.zig");
pub const bubblewrap = @import("bubblewrap.zig");
pub const docker = @import("docker.zig");
pub const detect = @import("detect.zig");

// Re-exports for convenience
pub const AuditEvent = audit.AuditEvent;
pub const AuditEventType = audit.AuditEventType;
pub const AuditLogger = audit.AuditLogger;
pub const AuditConfig = audit.AuditConfig;
pub const Actor = audit.Actor;
pub const Action = audit.Action;
pub const ExecutionResult = audit.ExecutionResult;
pub const SecurityContext = audit.SecurityContext;
pub const CommandExecutionLog = audit.CommandExecutionLog;

pub const AutonomyLevel = policy.AutonomyLevel;
pub const CommandRiskLevel = policy.CommandRiskLevel;
pub const SecurityPolicy = policy.SecurityPolicy;
pub const ActionTracker = policy.ActionTracker;

pub const PairingGuard = pairing.PairingGuard;
pub const constantTimeEq = pairing.constantTimeEq;
pub const isPublicBind = pairing.isPublicBind;

pub const SecretStore = secrets.SecretStore;
pub const encrypt = secrets.encrypt;
pub const decrypt = secrets.decrypt;
pub const hmacSha256 = secrets.hmacSha256;
pub const hexEncode = secrets.hexEncode;
pub const hexDecode = secrets.hexDecode;

pub const Sandbox = sandbox.Sandbox;
pub const NoopSandbox = sandbox.NoopSandbox;
pub const createNoopSandbox = sandbox.createNoopSandbox;
pub const createSandbox = sandbox.createSandbox;
pub const SandboxBackend = sandbox.SandboxBackend;
pub const SandboxStorage = sandbox.SandboxStorage;
pub const detectAvailable = sandbox.detectAvailable;
pub const AvailableBackends = sandbox.AvailableBackends;

pub const LandlockSandbox = landlock.LandlockSandbox;
pub const FirejailSandbox = firejail.FirejailSandbox;
pub const BubblewrapSandbox = bubblewrap.BubblewrapSandbox;
pub const DockerSandbox = docker.DockerSandbox;

pub const RateTracker = tracker.RateTracker;

test {
    // Run tests from all submodules
    @import("std").testing.refAllDecls(@This());
}
