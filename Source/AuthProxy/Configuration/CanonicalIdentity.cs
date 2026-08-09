// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Configuration;

/// <summary>
/// Configures the stable, provider-aware identity asserted after a provider has authenticated a principal.
/// </summary>
/// <remarks>
/// This configuration selects authentication metadata only. It does not establish application membership,
/// roles, scopes, authorization, or ownership of personally identifiable information.
/// </remarks>
public class CanonicalIdentity
{
    /// <summary>
    /// Gets or sets the stable provider key. It must already be lowercase ASCII and may contain letters,
    /// digits, periods, underscores, and hyphens. It is independent of the display name and ASP.NET scheme.
    /// </summary>
    public string ProviderKey { get; set; } = string.Empty;

    /// <summary>
    /// Gets or sets the exact claim type that supplies the provider subject.
    /// Exactly one nonempty claim of this type must exist; AuthProxy never falls back to an email or name.
    /// </summary>
    public string SubjectClaimType { get; set; } = string.Empty;

    /// <summary>
    /// Gets or sets the explicit issuer for an OAuth provider whose authenticated user-info response does not
    /// carry a framework-validated issuer. OIDC providers must leave this unset and use their validated token issuer.
    /// </summary>
    public string? Issuer { get; set; }
}
