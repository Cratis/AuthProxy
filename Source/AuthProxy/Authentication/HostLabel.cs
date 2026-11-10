// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Authentication;

/// <summary>
/// A single DNS-style host label such as a tenant sub-domain.
/// </summary>
/// <param name="Value">The label text.</param>
readonly record struct HostLabel(string Value)
{
    /// <summary>
    /// Gets a value indicating whether the label is non-blank, contains only letters, digits and hyphens, and neither starts nor ends with a hyphen.
    /// </summary>
    public bool IsValid =>
        !string.IsNullOrWhiteSpace(Value)
        && !Value.StartsWith('-')
        && !Value.EndsWith('-')
        && Value.All(character => char.IsLetterOrDigit(character) || character == '-');

    /// <summary>
    /// Wraps a host label.
    /// </summary>
    /// <param name="value">The label text.</param>
    public static implicit operator HostLabel(string value) => new(value);

    /// <summary>
    /// Prefixes this label onto a parent host.
    /// </summary>
    /// <param name="parentHost">The parent host.</param>
    /// <returns>The combined host name.</returns>
    public string Under(string parentHost) => $"{Value}.{parentHost}";
}
