const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const lib = b.addLibrary(.{
        .name = "sqlite3",
        .root_module = b.createModule(.{
            .target = target,
            .optimize = optimize,
            .link_libc = true,
        }),
    });
    lib.root_module.addCSourceFile(.{
        .file = b.path("sqlite3.c"),
    });
    lib.installHeader(b.path("sqlite3.h"), "sqlite3.h");
    lib.installHeader(b.path("sqlite3ext.h"), "sqlite3ext.h");
    b.installArtifact(lib);
}
