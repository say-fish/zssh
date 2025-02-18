//! Type classes *ALIKE* for Zig. This provides facilities for explicit compile
//! time type "interfaces".

const std = @import("std");

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

pub fn Struct(comptime T: type) type {
    if (std.meta.activeTag(@typeInfo(T)) != .@"struct")
        @compileError(@typeName(T) ++ "is not a struct");

    return T;
}

pub fn Enum(comptime T: type) type {
    if (std.meta.activeTag(@typeInfo(T)) != .@"enum")
        @compileError(@typeName(T) ++ "is not an enum");

    return T;
}

pub fn member(comptime T: type, comptime name: []const u8) type {
    if (!@hasDecl(T, name))
        @compileError(@typeName(T) ++ " has no declaration named " ++ name);

    return @field(T, name);
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

pub fn is_array(comptime T: type) bool {
    return @typeInfo(T) == .array;
}

/// Assumes T is an array
pub fn array_len(comptime T: type) comptime_int {
    return @typeInfo(T).array.len;
}
