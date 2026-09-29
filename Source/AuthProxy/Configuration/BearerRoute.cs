// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Configuration;

/// <summary>
/// Represents a path prefix on a service that is authenticated by an access token from an external authorization
/// server instead of by a browser session.
/// </summary>
/// <remarks>
/// On a bearer route a valid access token is the only credential: the session cookie is never read, no provider
/// selection or tenant selection is ever served, and every refusal is an API-style <c language="text">401</c> or
/// <c language="text">403</c> with an RFC 6750 challenge. Tokens from the configured issuers are refused on every path
/// that is not one of their bearer routes, so a token cannot reach a browser-only surface.
/// </remarks>
public class BearerRoute
{
    /// <summary>
    /// The identity provider label the forwarded principal carries when <see cref="IdentityProvider"/> is unset.
    /// </summary>
    public const string DefaultIdentityProvider = "bearer";

    /// <summary>
    /// The token claim the tenant is read from when <see cref="TenantClaimType"/> is unset.
    /// </summary>
    public const string DefaultTenantClaimType = "tid";

    /// <summary>
    /// The clock skew allowed when <see cref="ClockSkew"/> is unset.
    /// </summary>
    public static readonly TimeSpan DefaultClockSkew = TimeSpan.FromSeconds(30);

    /// <summary>
    /// The largest clock skew a route may allow.
    /// </summary>
    public static readonly TimeSpan MaximumClockSkew = TimeSpan.FromMinutes(5);

    /// <summary>
    /// Gets or sets the path prefix this route covers, for example <c language="text">/mcp</c> or <c language="text">/v1</c>. Matched
    /// case-insensitively on segment boundaries, with the same rules as <see cref="Service.AnonymousPaths"/>.
    /// </summary>
    public string PathPrefix { get; set; } = string.Empty;

    /// <summary>
    /// Gets or sets the authorization servers whose tokens this route accepts.
    /// </summary>
    public IList<BearerIssuer> Issuers { get; set; } = [];

    /// <summary>
    /// Gets or sets the audiences this route accepts. A token is accepted only when its <c language="text">aud</c> claim names
    /// at least one of them.
    /// </summary>
    public IList<string> Audiences { get; set; } = [];

    /// <summary>
    /// Gets or sets the scopes a token must carry, every one of them, to be accepted on this route. Leave empty to
    /// require none.
    /// </summary>
    public IList<string> RequiredScopes { get; set; } = [];

    /// <summary>
    /// Gets or sets the absolute URL of this route's RFC 9728 protected-resource metadata document. It is named in
    /// the <c language="text">resource_metadata</c> parameter of every challenge on this route, and its path is forwarded to
    /// the service's backend without authentication.
    /// </summary>
    public string? ResourceMetadataUrl { get; set; }

    /// <summary>
    /// Gets or sets the token claim that carries the tenant. Defaults to <see cref="DefaultTenantClaimType"/>.
    /// </summary>
    public string TenantClaimType { get; set; } = DefaultTenantClaimType;

    /// <summary>
    /// Gets or sets the claims to rewrite before the principal is forwarded: forwarded claim type to the token claim
    /// it is read from. A mapped source claim the token does not carry refuses the token.
    /// </summary>
    public IDictionary<string, string> ClaimMappings { get; set; } = new Dictionary<string, string>();

    /// <summary>
    /// Gets or sets the identity provider label of the forwarded principal. Defaults to
    /// <see cref="DefaultIdentityProvider"/>.
    /// </summary>
    public string IdentityProvider { get; set; } = DefaultIdentityProvider;

    /// <summary>
    /// Gets or sets a value indicating whether the <c language="text">Authorization</c> header is forwarded to the backend.
    /// Defaults to <see langword="false"/>: the backend receives the principal AuthProxy vouches for, not the token.
    /// </summary>
    public bool ForwardAuthorizationHeader { get; set; }

    /// <summary>
    /// Gets or sets the clock skew allowed when checking the token lifetime. Defaults to
    /// <see cref="DefaultClockSkew"/>; at most <see cref="MaximumClockSkew"/>.
    /// </summary>
    public TimeSpan? ClockSkew { get; set; }
}
