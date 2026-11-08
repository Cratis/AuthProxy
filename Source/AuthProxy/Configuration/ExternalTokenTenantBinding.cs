// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Configuration;

/// <summary>
/// Binds tokens accepted by the general JWT Bearer handler to an AuthProxy tenant.
/// </summary>
public class ExternalTokenTenantBinding
{
    /// <summary>Gets or sets whether an authenticated token must establish its tenant.</summary>
    public bool Require { get; set; }

    /// <summary>Gets or sets the exact claim type carrying the external tenant identifier.</summary>
    public string TenantClaimType { get; set; } = "tid";

    /// <summary>
    /// Gets or sets the exact, case-sensitive external-to-AuthProxy tenant mapping.
    /// An empty mapping uses the claim value directly.
    /// </summary>
    public IDictionary<string, string> TenantMapping { get; set; } = new Dictionary<string, string>(StringComparer.Ordinal);
}
