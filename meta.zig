//! Type classes *ALIKE* for Zig. This provides facilities for explicit compile
//! type "interfaces".

const std = @import("std");

pub fn ForAll(pred: fn (comptime type) type, comptime T: type) type {
    for (std.meta.fields(T)) |field| {
        _ = pred(field.type);
    }

    return T;
}

pub fn All(comptime T: type, comptime preds: anytype) type {
    // const fields_info = @typeInfo(@TypeOf(preds)).@"struct".fields;

    for (std.meta.fields(@TypeOf(preds))) |field| {
        _ = @as(
            *field.type,
            @alignCast(@constCast(@ptrCast(field.default_value_ptr.?))),
        )(T);
    }

    return T;
}

pub fn Struct(comptime T: type) type {
    if (std.meta.activeTag(@typeInfo(T)) != .@"struct")
        @compileError(@typeName(T) ++ "is not a struct");

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
