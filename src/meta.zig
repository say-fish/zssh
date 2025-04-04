//! Type classes *ALIKE* for Zig. This provides facilities for explicit compile
//! time type "interfaces". This avoids convoluted checks with `@hasDecl` and
//! alike. While making debugging a little bit easier, since now the type
//! requirements are explicit in the function declaration or use site.
//!
//! For this to work with Zig, the type must be threaded through a function that
//! checks the type constraints, i.e.
//!
//! ```zig
//!
//! fn foo(comptime T: type, value: And(T, .{Decl("foo"), Decl("bar")})) void {
//!     // Here, we are sure that `value: T` has the fields `fod` and `bar`
//!     // access
//! }
//! ```

const std = @import("std");

/// Checks if a given predicate `pred` is valid for all instances in type T,
/// for structs, enums, and unions this means checking all fields in the type
/// match the predicate.
pub fn ForAll(pred: fn (comptime type) type, comptime T: type) type {
    switch (@typeInfo(T)) {
        .@"struct", .@"enum", .@"union" => {
            for (std.meta.fields(T)) |field| {
                _ = pred(field.type);
            }
        },
        else => _ = pred(T),
    }

    return T;
}

pub fn And(comptime T: type, comptime preds: anytype) type {
    const pred_type = fn (comptime type) type;

    for (std.meta.fields(@TypeOf(preds))) |field| {
        if (field.type != pred_type) {
            @compileError(@typeName(field.type) ++
                " does not match predicate " ++
                @typeName(pred_type));
        }

        const func = @as(
            *field.type,
            @alignCast(@constCast(@ptrCast(field.default_value_ptr.?))),
        );

        _ = func(T);
    }

    return T;
}

pub fn Container(comptime T: type) type {
    return switch (@typeInfo(T)) {
        .@"struct", .@"enum", .@"union" => T,
        else => @compileError(@typeName(T) ++ "is not a Container."),
    };
}

pub fn member(comptime T: type, comptime name: []const u8) type {
    if (!@hasDecl(T, name))
        @compileError(@typeName(T) ++ " has no declaration named " ++ name);

    return @field(T, name);
}

pub fn Decl(comptime name: []const u8) fn (comptime type) type {
    return struct {
        fn Inner(comptime T: []const u8) type {
            if (!@hasDecl(T, name))
                @compileError(@typeName(T) ++ " has no declaration named " ++ name);

            return T;
        }
    }.Inner;
}

pub fn decl(comptime T: type, comptime name: []const u8) type {
    if (!@hasDecl(T, name))
        @compileError(@typeName(T) ++ " does not declare " ++ name);

    return @TypeOf(@field(T, name));
}

pub fn has_decl(
    comptime T: type,
    comptime decl_name: []const u8,
    comptime decl_type: type,
) type {
    // TODO: We should allow for callconv(.*)
    const declaration = decl(T, decl_name);

    if (declaration != decl_type)
        @compileError(
            @typeName(T) ++ " does not declare " ++
                @typeName(decl_type) ++ ", got: " ++
                @typeName(declaration),
        );

    return T;
}

/// Checks and return T if its of type given by tag
pub fn Is(comptime tag: std.meta.Tag(std.builtin.Type), comptime T: type) type {
    if (!is(tag, T))
        @compileError(@typeName(T) ++ "is not " ++ @tagName(tag));

    return T;
}

/// Returns true if T is of type given by tag
pub fn is(comptime tag: std.meta.Tag(std.builtin.Type), comptime T: type) bool {
    return tag == @typeInfo(T);
}

pub fn array_len(comptime T: type) comptime_int {
    return @typeInfo(Is(.array, T)).array.len;
}
