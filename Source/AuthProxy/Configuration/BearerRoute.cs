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
    /// it is read from, replacing all case variants of the target. A missing source refuses the token, as do
    /// multiple usable source values for mapped sub, preferred_username or name. Targets may not differ only
    /// by case or overwrite the tenant claim.
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

    /// <summary>
    /// Gets or sets claim requirements of this route's own, which the token's principal must satisfy after
    /// <see cref="ClaimMappings"/> — every one of them, in addition to whatever deployment requirements apply.
    /// </summary>
    /// <remarks>
    /// Composed exactly like <see cref="Authorization.RequiredClaims"/>: the list is an <em>and</em>, each
    /// requirement's <see cref="ClaimRequirement.AnyOf"/> an <em>or</em>. A token never carries a role, so a
    /// requirement on a role claim is refused at startup.
    /// </remarks>
    public IList<ClaimRequirement> RequiredClaims { get; set; } = [];

    /// <summary>
    /// Gets or sets a value indicating whether the deployment's claim requirements — the proxy-wide
    /// <see cref="AuthProxy.Authorization"/> and the route's service's own — are left out on this route.
    /// Defaults to <see langword="false"/>: they apply to a bearer token as they do to a browser session.
    /// </summary>
    /// <remarks>
    /// For a deployment whose requirements name a claim only its browser sign-in produces — a GitHub team read
    /// from the GitHub API, say — and which the token issuer does not mint. Without this, every token on the
    /// route would be refused. Setting it widens who reaches the service through this route, so AuthProxy logs a
    /// warning at startup naming the requirements it leaves out; state what the route requires instead in
    /// <see cref="RequiredClaims"/>.
    /// </remarks>
    public bool IgnoreDeploymentRequiredClaims { get; set; }

    /// <summary>
    /// Gets or sets a value indicating whether this route accepts callers without asking any service's
    /// <c language="text">/.cratis/me</c> about them. Defaults to <see langword="false"/>.
    /// </summary>
    /// <remarks>
    /// A bearer route never calls <c language="text">/.cratis/me</c>, in either <see cref="IdentityVerificationMode"/>: the
    /// endpoint answers for browser sessions, and a product cannot be assumed to answer it correctly for a principal
    /// authenticated by a token. Setting this states that for this route the validated token, its scopes and the
    /// claim requirements are the whole decision at the edge, and that the backend decides tenant membership and
    /// everything else.
    /// <para>
    /// When any service declares <see cref="IdentityVerificationMode.Required"/>, every forwarded request is meant to
    /// carry a positive verdict, so a bearer route in that deployment is refused at startup unless it sets this.
    /// Under <see cref="IdentityVerificationMode.BestEffort"/>, where an HTTP <c language="text">403</c> from
    /// <c language="text">/.cratis/me</c> refuses a browser session, a route that does not set this is started with a
    /// warning that the refusal does not apply to its tokens.
    /// </para>
    /// </remarks>
    public bool AcceptWithoutIdentityVerification { get; set; }
}
