//! Shared thread stack budgets by operational role.
//!
//! Keep repeated `std.Thread.spawn` sizes aligned across runtime code and
//! tests, and make intent visible at the call site.

/// Queue/mutex coordination, short-lived test helpers, and other tiny worker
/// tasks that do not enter the full agent/runtime path.
pub const COORDINATION_STACK_SIZE: usize = 64 * 1024;

/// Typing indicators, heartbeats, and similarly small auxiliary loops.
pub const AUXILIARY_LOOP_STACK_SIZE: usize = 128 * 1024;

/// Supervisors, readers, pollers, and other medium-weight control loops.
pub const CONTROL_LOOP_STACK_SIZE: usize = 256 * 1024;

/// Daemon-owned services such as the HTTP gateway, scheduler, and channel
/// supervisor. These traverse deeper webhook, cron, and channel bootstrap
/// paths than generic control loops.
pub const DAEMON_SERVICE_STACK_SIZE: usize = 1024 * 1024;

/// Long-lived network/runtime threads such as channel gateways, outbound
/// dispatch, and subagents.
pub const HEAVY_RUNTIME_STACK_SIZE: usize = 2 * 1024 * 1024;

/// Dedicated threads that execute `SessionManager.processMessage*()` /
/// `Agent.turn()`. Keep this aligned with the heavy runtime budget.
pub const SESSION_TURN_STACK_SIZE: usize = HEAVY_RUNTIME_STACK_SIZE;
