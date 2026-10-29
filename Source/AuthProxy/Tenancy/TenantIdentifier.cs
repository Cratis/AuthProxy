// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Buffers;

namespace Cratis.AuthProxy.Tenancy;

/// <summary>
/// The single rule a tenant identifier has to follow, whichever strategy produced it.
/// </summary>
public static class TenantIdentifier
{
    /// <summary>
    /// The longest tenant identifier accepted.
    /// </summary>
    public const int MaximumLength = 256;

    static readonly SearchValues<char> _allowedCharacters = SearchValues.Create(
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~");

    /// <summary>
    /// Gets whether a value is usable as a tenant identifier: not empty, not a dot segment, at most
    /// <see cref="MaximumLength"/> characters, and only letters, digits and <c language="text">-._~</c>.
    /// </summary>
    /// <param name="value">The value to check.</param>
    /// <returns><see langword="true"/> when the value is usable; otherwise <see langword="false"/>.</returns>
    public static bool IsUsable(string? value) =>
        !string.IsNullOrEmpty(value)
        && value is not "." and not ".."
        && value.Length <= MaximumLength
        && value.AsSpan().IndexOfAnyExcept(_allowedCharacters) < 0;
}
