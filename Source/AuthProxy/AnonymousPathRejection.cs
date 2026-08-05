// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy;

/// <summary>
/// Represents why a declared anonymous path was refused.
/// </summary>
/// <remarks>
/// A refused entry leaves its path authenticated, which is the safe outcome but an invisible one — the
/// operator declared a path public and it silently is not. Naming the reason is what makes the refusal
/// reportable, so <c>MicroserviceReverseProxyConfigProvider</c> can say which entry was dropped and why
/// rather than leaving it to be discovered from a login prompt on a path that was meant to be open.
/// </remarks>
public enum AnonymousPathRejection
{
    /// <summary>The entry is usable and was not refused.</summary>
    None = 0,

    /// <summary>The entry was blank, or whitespace only.</summary>
    Empty = 1,

    /// <summary>The entry does not start with <c>/</c>.</summary>
    NotRooted = 2,

    /// <summary>The entry resolves to the application root, which would make the whole service anonymous.</summary>
    Root = 3,

    /// <summary>The entry contains an empty segment, from a repeated <c>/</c>.</summary>
    EmptySegment = 4,

    /// <summary>The entry contains a <c>.</c> or <c>..</c> segment.</summary>
    DotSegment = 5,

    /// <summary>The entry contains a character outside the permitted set.</summary>
    DisallowedCharacter = 6,

    /// <summary>The entry overlaps a path prefix AuthProxy answers itself.</summary>
    ProxyOwnedPath = 7,
}
