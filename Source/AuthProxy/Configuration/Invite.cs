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
    /// Gets or sets the absolute URL of the Studio invite-exchange endpoint,
    /// e.g. <c>https://studio.example.com/internal/invites/exchange</c>.
    /// </summary>
    public string ExchangeUrl { get; set; } = string.Empty;

    /// <summary>
    /// Gets or sets the claim name in the invite token that holds the tenant ID.
    /// When set, a tenant-issued invite is recognized when this claim's value matches
    /// the resolved tenant. If they match the invite bypasses the lobby redirect and
    /// the user proceeds directly to the microservice.
    /// Leave empty to disable tenant-issued invite detection.
    /// </summary>
    public string TenantClaim { get; set; } = string.Empty;

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
    /// Gets or sets the lobby service configuration.
    /// When set, requests from users without a resolved tenant are forwarded to this service's frontend,
    /// and users are redirected here after a successful invite exchange.
    /// </summary>
    public Service? Lobby { get; set; }
}
