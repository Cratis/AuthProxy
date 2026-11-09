// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.ForwardedIdentity;

/// <summary>
/// Immutable evidence supplied only by a trusted credential pipeline, never reconstructed from request headers.
/// No built-in authentication flow supplies this context yet; v2 refuses requests without it.
/// </summary>
/// <param name="CredentialKind">The verified credential classification.</param>
/// <param name="CredentialId">The non-secret authoritative credential record identifier.</param>
/// <param name="SenderBinding">Verified sender evidence, or the explicit unbound value <c language="text">none</c>.</param>
public sealed record ForwardedIdentityTrustedContext(string CredentialKind, string CredentialId, string SenderBinding)
{
    /// <summary>Gets the request-local slot populated by the trusted producer before final signing.</summary>
    public static HttpRequestOptionsKey<ForwardedIdentityTrustedContext> OptionsKey { get; } = new("Cratis.AuthProxy.ForwardedIdentity.TrustedContext");

    /// <summary>Gets the allowlisted realm issuer from trusted configuration, not from legacy provider claims.</summary>
    public string? TrustedRealmIssuer { get; init; }

    /// <summary>Gets the preserved person and authentication evidence; absent for service callers.</summary>
    public ForwardedIdentityPersonEvidence? Person { get; init; }

    /// <summary>Gets optional standard-base64 UTF-8 JSON authentication methods.</summary>
    public string? AuthenticationMethods { get; init; }

    /// <summary>Gets optional standard-base64 UTF-8 JSON current actor evidence.</summary>
    public string? Actor { get; init; }

    /// <summary>Gets the checked authoritative bounded grant reference.</summary>
    public string? GrantId { get; init; }

    /// <summary>Gets the checked organisation-policy revision, when applicable.</summary>
    public string? PolicyEpoch { get; init; }

    /// <summary>Gets the receiving host's configured tenancy header.</summary>
    public string TenantHeader { get; init; } = Headers.TenantId;

    /// <summary>Gets evidence of local verification of the exact forwarded bearer; absent when no bearer is sent.</summary>
    public ForwardedIdentityVerifiedBearer? Bearer { get; init; }

    /// <summary>Gets the fixed deadline for a queued callback snapshot; retries must not renew it.</summary>
    internal DateTimeOffset? SnapshotExpiresUtc { get; init; }

    /// <inheritdoc/>
    public override string ToString() => nameof(ForwardedIdentityTrustedContext);
}
