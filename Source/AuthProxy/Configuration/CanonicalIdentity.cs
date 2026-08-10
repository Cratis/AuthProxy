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
    /// Gets or sets a value indicating whether this provider is eligible to complete signed invitations.
    /// </summary>
    /// <remarks>
    /// The default is <see langword="false"/>. Enable it only when the provider registration can produce the exact
    /// verified email evidence configured below. The provider remains available for ordinary sign-in when disabled.
    /// </remarks>
    public bool InvitationCompletionEnabled { get; set; }

    /// <summary>
    /// Gets or sets a value indicating whether this provider is eligible to complete invitations that are
    /// immutably bound to a provider subject by the invitation issuer.
    /// </summary>
    /// <remarks>
    /// The default is <see langword="false"/>. This mode does not treat an email address as identity evidence.
    /// Enable it only when the provider yields an immutable, tenant-scoped subject and a framework-validated issuer.
    /// </remarks>
    public bool InvitationIdentityBindingCompletionEnabled { get; set; }

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
    /// Gets or sets the exact provider-derived claim type that supplies the email address for an invitation
    /// attestation. The default is <c>email</c>.
    /// </summary>
    public string EmailClaimType { get; set; } = "email";

    /// <summary>
    /// Gets or sets the exact provider-derived claim type that proves the email address is verified.
    /// The claim must occur exactly once with the value <see langword="true"/>. The default is <c>email_verified</c>.
    /// </summary>
    public string EmailVerifiedClaimType { get; set; } = "email_verified";

    /// <summary>
    /// Gets or sets the exact provider-derived claim type that describes authentication assurance.
    /// </summary>
    /// <remarks>
    /// OIDC providers commonly use <c>acr</c>. OAuth providers can map a trustworthy user-information field to
    /// this claim. AuthProxy refuses an invitation completion when the configured claim is missing or ambiguous.
    /// </remarks>
    public string AssuranceClaimType { get; set; } = "acr";

    /// <summary>
    /// Gets or sets the explicit issuer for an OAuth provider whose authenticated user-info response does not
    /// carry a framework-validated issuer. OIDC providers must leave this unset and use their validated token issuer.
    /// </summary>
    public string? Issuer { get; set; }
}
