// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Configuration;

/// <summary>
/// Represents the configuration for the invite system.
/// </summary>
public class Invite
{
    /// <summary>
    /// Gets or sets the RSA public key PEM used to verify invite token signatures.
    /// </summary>
    public string PublicKeyPem { get; set; } = string.Empty;

    /// <summary>
    /// Gets or sets the expected token issuer (<c>iss</c> claim).
    /// Leave empty to skip issuer validation.
    /// </summary>
    public string Issuer { get; set; } = string.Empty;

    /// <summary>
    /// Gets or sets the expected token audience (<c>aud</c> claim).
    /// Leave empty to skip audience validation.
    /// </summary>
    public string Audience { get; set; } = string.Empty;

    /// <summary>
    /// Gets or sets the absolute URL of the invitation authority's completion endpoint,
    /// e.g. <c>https://lobby.example.com/_invite/exchange</c>.
    /// </summary>
    public string ExchangeUrl { get; set; } = string.Empty;

    /// <summary>
    /// Gets or sets the absolute URL of the same invitation authority's staging endpoint.
    /// </summary>
    /// <remarks>
    /// AuthProxy calls this endpoint before starting provider authentication. The call binds the exact invitation
    /// capability to a new transaction and challenge under a signed stage attestation.
    /// </remarks>
    public string StageUrl { get; set; } = string.Empty;

    /// <summary>
    /// Gets or sets the signed invitation-attestation configuration.
    /// </summary>
    /// <remarks>
    /// Configure this together with <see cref="StageUrl"/> to enable the two-stage, positively authenticated
    /// invitation protocol. Without it, AuthProxy retains the released legacy exchange for compatibility; do not
    /// use that legacy mode as an authority for creating or linking an account.
    /// </remarks>
    public InvitationAttestation? Attestation { get; set; }

    /// <summary>
    /// Gets or sets the URL to redirect to when the authenticated user's subject is already
    /// associated with an existing user during the invite exchange (Phase 2).
    /// When set, the user is redirected to this URL instead of the built-in
    /// <c>invitation-subject-already-exists.html</c> page.
    /// Leave empty to serve the built-in well-known error page.
    /// </summary>
    public string SubjectAlreadyExistsUrl { get; set; } = string.Empty;

    /// <summary>
    /// Gets or sets the claim name in the invite token that holds the tenant ID.
    /// When set, a tenant-issued invite is recognized when this claim's value matches
    /// the resolved tenant. If they match the invite bypasses the lobby redirect and
    /// the user proceeds directly to the microservice.
    /// Leave empty to disable tenant-issued invite detection.
    /// </summary>
    public string TenantClaim { get; set; } = string.Empty;

    /// <summary>
    /// Gets or sets the claim name in the invite token that holds the email address for which the invitation
    /// was issued. An empty value disables AuthProxy's email-binding enforcement. When configured and present
    /// in a validated invite token, AuthProxy compares it with provider-supplied email evidence from the
    /// authenticated session before the Phase-2 exchange. The provider-supplied address and its reported
    /// verification status are forwarded to the exchange endpoint regardless of this setting.
    /// </summary>
    /// <remarks>
    /// AuthProxy reads the address from <c>email</c>, then <c>ClaimTypes.Email</c>, and finally
    /// <c>preferred_username</c> only when that value has an email-address shape. If no address is available,
    /// AuthProxy rejects the invite with <c>invitation-email-unavailable.html</c>. If the address differs from
    /// the invited address, or the provider explicitly supplies <c>email_verified=false</c>, AuthProxy rejects
    /// it with <c>invitation-email-mismatch.html</c>.
    /// <para>
    /// The <c>email_verified</c> claim is provider-supplied evidence, not a universal AuthProxy attestation.
    /// An explicit <see langword="false"/> is rejected; a missing or unparsable value is forwarded as
    /// <see langword="null"/> and does not independently prove ownership. OAuth provider registrations do not
    /// currently map <c>email_verified</c>, so their address is accepted as provider-supplied session evidence
    /// with a <see langword="null"/> verification status. For example, GitHub's <c>/user</c> response can omit
    /// a private email address, and AuthProxy does not make a separate <c>/user/emails</c> request.
    /// </para>
    /// </remarks>
    public string EmailClaim { get; set; } = string.Empty;

    /// <summary>
    /// Gets or sets a value indicating whether the invitation ID from the invite token (<c>jti</c>)
    /// should be appended to the lobby redirect URL query string after a successful invite exchange.
    /// Defaults to <see langword="false"/>.
    /// </summary>
    public bool AppendInvitationIdToQueryString { get; set; }

    /// <summary>
    /// Gets or sets the query-string key used when <see cref="AppendInvitationIdToQueryString"/> is enabled.
    /// Defaults to <c>invitationId</c>.
    /// </summary>
    public string InvitationIdQueryStringKey { get; set; } = "invitationId";

    /// <summary>
    /// Gets or sets a value indicating whether unresolved-tenant requests should redirect to the lobby frontend.
    /// Defaults to <see langword="false"/> so unresolved tenants stay in the current proxy and receive
    /// the proxy's local response behavior.
    /// </summary>
    public bool RedirectToLobbyWhenTenantUnresolved { get; set; }

    /// <summary>
    /// Gets or sets claim mappings to forward values from the invite token into
    /// the principal sent to the identity details provider.
    /// This allows invite claims and identity-provider claims to be combined in a configurable way.
    /// </summary>
    public IList<InviteClaimForwarding> ClaimsToForward { get; set; } = [];

    /// <summary>
    /// Gets or sets the lobby service configuration.
    /// When set, requests from users without a resolved tenant are forwarded to this service's frontend,
    /// invite exchanges return here, and registrations can redirect to its configured registration endpoint.
    /// </summary>
    public Service? Lobby { get; set; }
}
