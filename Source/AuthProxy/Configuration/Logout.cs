// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Configuration;

/// <summary>
/// Represents the configuration for the logout endpoint.
/// </summary>
public class Logout
{
    /// <summary>
    /// Gets or sets additional origins permitted as post-logout redirect targets.
    /// Each entry is an absolute origin (scheme and host, optionally a port), e.g. <c>https://cratis.studio</c>.
    /// These are added to the implicit allow-list — the proxy's own public origin plus the configured
    /// service frontends and lobby frontend. Malformed or non-HTTP(S) entries are ignored.
    /// </summary>
    public IList<string> AllowedRedirectOrigins { get; set; } = [];
}
