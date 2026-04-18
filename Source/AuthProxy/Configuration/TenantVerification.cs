// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Configuration;

/// <summary>
/// Represents the configuration for verifying that a resolved tenant exists in the system.
/// </summary>
public class TenantVerification
{
    /// <summary>
    /// Gets or sets the URL template used to verify tenant existence.
    /// Use <c>{tenantId}</c> as a placeholder for the resolved tenant identifier,
    /// e.g. <c>https://platform.example.com/api/tenants/{tenantId}</c>.
    /// An HTTP GET to the resolved URL must return <c>200</c> when the tenant exists
    /// and <c>404</c> when it does not.
    /// </summary>
    public string UrlTemplate { get; set; } = string.Empty;
}
