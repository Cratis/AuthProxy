// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Configuration;

/// <summary>Opts an OAuth-only route into RFC 9449 proof verification.</summary>
public sealed class BearerRouteDpop
{
    /// <summary>Gets or sets whether unbound Bearer tokens remain eligible. Defaults to Accept.</summary>
    public DpopMode Mode { get; set; }

    /// <summary>Gets or sets the trusted HTTPS public origin, without a trailing slash, path, query or fragment.</summary>
    public string PublicOrigin { get; set; } = string.Empty;

    /// <summary>Gets or sets the optional public path replacing this route's internal mount.</summary>
    public string? PublicPathPrefix { get; set; }
}
