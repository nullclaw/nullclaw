//! verbose.zig - Verbose logging control
//! 
//! This module provides thread-safe functions to control and check verbose logging status.
//! The verbose flag is used to enable detailed debug output across the application.

const std = @import("std");

/// Atomic flag to track if verbose logging is enabled
var verbose_enabled: std.atomic.Value(bool) = std.atomic.Value(bool).init(false);

/// Set the verbose logging status
/// 
/// Args:
///   enabled: Whether to enable verbose logging
pub fn setVerbose(enabled: bool) void {
    verbose_enabled.store(enabled, .release);
}

/// Check if verbose logging is enabled
/// 
/// Returns:
///   bool: True if verbose logging is enabled, false otherwise
pub fn isVerbose() bool {
    return verbose_enabled.load(.acquire);
}
