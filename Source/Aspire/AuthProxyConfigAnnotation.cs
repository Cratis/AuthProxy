// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Aspire;

/// <summary>
/// Annotation that tracks per-resource state used when building array-based AuthProxy configuration
/// (e.g. OIDC/OAuth providers, tenant resolution strategies).
/// </summary>
sealed class AuthProxyConfigAnnotation : IResourceAnnotation
{
    /// <summary>Gets or sets the number of OIDC providers that have been registered.</summary>
    public int OidcProviderCount { get; set; }

    /// <summary>Gets or sets the number of OAuth providers that have been registered.</summary>
    public int OAuthProviderCount { get; set; }

    /// <summary>Gets or sets the number of tenant resolution strategies that have been registered.</summary>
    public int TenantResolutionCount { get; set; }
}
