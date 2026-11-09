// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Configuration;

/// <summary>Requires a recent authentication before a protected service path can be accessed.</summary>
public class FreshAuthenticationRule
{
    /// <summary>Gets or sets the service-local path. The root path matches the whole service.</summary>
    public string Path { get; set; } = string.Empty;

    /// <summary>Gets or sets whether to match the path and its descendants instead of only the exact path.</summary>
    public bool Prefix { get; set; }

    /// <summary>Gets or sets the HTTP methods to match. An empty array matches every method.</summary>
    /// <remarks>
    /// GET, HEAD, OPTIONS and TRACE match only their own rules. Other methods match the union of rules
    /// declaring any non-safe method on the path, using the strictest age, regardless of method overrides.
    /// </remarks>
    public IList<string> Methods { get; set; } = [];

    /// <summary>Gets or sets the maximum authentication age, from one second through one day. Defaults to five minutes.</summary>
    public TimeSpan MaxAge { get; set; } = TimeSpan.FromMinutes(5);
}
