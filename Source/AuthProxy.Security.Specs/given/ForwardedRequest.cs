// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Security.given;

/// <summary>
/// Represents a request as the origin behind AuthProxy received it.
/// </summary>
/// <param name="Method">The HTTP method.</param>
/// <param name="Path">The request path.</param>
/// <param name="QueryString">The query string, including the leading <c>?</c> when present.</param>
/// <param name="Headers">Every header the origin received, keyed case-insensitively.</param>
public sealed record ForwardedRequest(
    string Method,
    string Path,
    string QueryString,
    IReadOnlyDictionary<string, string> Headers)
{
    /// <summary>
    /// Gets whether the origin received the named header.
    /// </summary>
    /// <param name="name">The header name.</param>
    /// <returns><see langword="true"/> when the header was present; otherwise <see langword="false"/>.</returns>
    public bool Has(string name) => Headers.ContainsKey(name);

    /// <summary>
    /// Gets the value the origin received for a header, or an empty string when it was absent.
    /// </summary>
    /// <param name="name">The header name.</param>
    /// <returns>The header value.</returns>
    public string Value(string name) => Headers.TryGetValue(name, out var value) ? value : string.Empty;
}
