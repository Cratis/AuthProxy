// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Net.Http.Headers;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using Cratis.AuthProxy.Authentication;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.JsonWebTokens;
using C = Cratis.AuthProxy.Configuration;

namespace Cratis.AuthProxy.Invites;

/// <summary>
/// The one implementation of the invitation exchange, shared by the post-login middleware and the provider
/// callback so both complete an invitation identically — claims forwarding, recipient binding, tenant
/// matching and duplicate-subject handling included.
/// </summary>
/// <param name="tokenValidator">The validator for invite JWT tokens.</param>
/// <param name="config">The auth proxy configuration monitor.</param>
/// <param name="authConfig">The authentication configuration monitor.</param>
/// <param name="tenantResolver">The tenant resolver, consulted when the tenancy middleware has not run for the current request.</param>
/// <param name="httpClientFactory">The HTTP client factory used for the exchange call.</param>
/// <param name="logger">The logger.</param>
/// <param name="canonicalIdentityResolver">The shared canonical identity resolver, or <see langword="null"/> for legacy-compatible direct construction.</param>
/// <param name="attestationIssuer">The signed invitation-attestation issuer, or <see langword="null"/> for legacy-compatible direct construction.</param>
/// <param name="entryStateProtector">The protected invitation-entry state service, or <see langword="null"/> for legacy-compatible direct construction.</param>
class InviteCompletion(
    IInviteTokenValidator tokenValidator,
    IOptionsMonitor<C.AuthProxy> config,
    IOptionsMonitor<C.Authentication> authConfig,
    ITenantResolver tenantResolver,
    IHttpClientFactory httpClientFactory,
    ILogger logger,
    ICanonicalIdentityResolver? canonicalIdentityResolver,
    IInvitationAttestationIssuer? attestationIssuer,
    IInvitationEntryStateProtector? entryStateProtector) : IInviteCompletion
{
    /// <summary>
    /// The upper bound on an attested invitation capability's length, applied before any parsing of it.
    /// </summary>
    internal const int MaximumAttestedInvitationTokenLength = 4096;

    /// <inheritdoc/>
    public async Task<InviteExchangeResult> ExchangeForRequest(HttpContext context, string inviteToken) =>
        IsAttestedProtocolEnabled()
            ? await CompleteAttestedInvitation(
                context,
                inviteToken,
                async () =>
                {
                    // The evidence is the established cookie session, authenticated by name so the question
                    // asked is exactly "what session is this request running as".
                    var authentication = await context.AuthenticateAsync(CookieAuthenticationDefaults.AuthenticationScheme);
                    return new InvitationCompletionSession(
                        authentication.Succeeded,
                        authentication.Principal,
                        authentication.Properties,
                        authentication.Properties?.IssuedUtc);
                })
            : await ExchangeInvite(inviteToken, context.User);

    /// <inheritdoc/>
    public async Task<InviteExchangeResult> ExchangeForTicket(HttpContext context, string inviteToken, ClaimsPrincipal principal, AuthenticationProperties properties) =>
        IsAttestedProtocolEnabled()
            ? await CompleteAttestedInvitation(
                context,
                inviteToken,
                () => Task.FromResult(new InvitationCompletionSession(
                    Succeeded: true,
                    principal,
                    properties,

                    // The ticket was received this instant; no handler has stamped an issue instant yet.
                    properties.IssuedUtc ?? DateTimeOffset.UtcNow)))
            : await ExchangeInvite(inviteToken, principal);

    /// <inheritdoc/>
    public bool TryResolveLobbyRedirect(HttpContext context, string inviteToken, out string lobbyRedirectUrl)
    {
        lobbyRedirectUrl = string.Empty;
        if (config.CurrentValue.Invite?.TenantIssuedInvitesSkipLobby == true
            && IsTenantIssuedInvite(inviteToken, context))
        {
            return false;
        }

        var lobbyUrl = config.CurrentValue.Invite?.Lobby?.Frontend?.BaseUrl;
        if (string.IsNullOrWhiteSpace(lobbyUrl))
        {
            return false;
        }

        lobbyRedirectUrl = BuildLobbyRedirectUrlWithInvitationId(lobbyUrl, inviteToken);
        return true;
    }

    /// <summary>
    /// Reads a claim that must occur exactly once in a token, refusing duplicates, padding and oversized values.
    /// </summary>
    /// <param name="token">The raw JWT string.</param>
    /// <param name="claimType">The claim type to look up.</param>
    /// <param name="value">The single exact claim value when accepted.</param>
    /// <returns><see langword="true"/> when the claim occurs exactly once with an acceptable value; otherwise <see langword="false"/>.</returns>
    internal static bool TryGetSingleTokenClaim(string token, string claimType, out string value)
    {
        value = string.Empty;
        try
        {
            var claims = new JsonWebTokenHandler().ReadJsonWebToken(token).Claims
                .Where(_ => string.Equals(_.Type, claimType, StringComparison.Ordinal))
                .ToArray();
            if (claims.Length != 1
                || string.IsNullOrWhiteSpace(claims[0].Value)
                || claims[0].Value.Length > 2048
                || !string.Equals(claims[0].Value, claims[0].Value.Trim(), StringComparison.Ordinal))
            {
                return false;
            }

            value = claims[0].Value;
            return true;
        }
        catch (ArgumentException)
        {
            return false;
        }
    }

    /// <summary>
    /// Determines whether the tenant the request is being served for matches an expected tenant, when one
    /// can be resolved at all.
    /// </summary>
    /// <param name="context">The current <see cref="HttpContext"/>.</param>
    /// <param name="tenantId">The tenant the invitation names.</param>
    /// <returns><see langword="true"/> when no tenant resolves for the request or the resolved tenant matches; otherwise <see langword="false"/>.</returns>
    internal bool ResolvedTenantMatchesWhenPresent(HttpContext context, string tenantId) =>
        !TryResolveTenant(context, out var resolvedTenantId)
        || FixedTimeEquals(tenantId, resolvedTenantId);

    /// <summary>
    /// Resolves the authenticating account's email and its provider-supplied verification status.
    /// </summary>
    /// <param name="principal">The authenticated principal completing the invitation.</param>
    /// <param name="emailVerified">
    /// The value of the provider's <c>email_verified</c> claim when present; otherwise <see langword="null"/>.
    /// </param>
    /// <returns>The authenticated email, or an empty string when none is available.</returns>
    /// <remarks>
    /// <c>preferred_username</c> is a username, not an address — for a GitHub OAuth provider it is conventionally
    /// mapped from <c>login</c>. It is read only when it actually holds an address, which several OIDC providers
    /// put there (Entra's is the user principal name). Returning a login name here would make a provider that
    /// supplied no address at all indistinguishable from one that supplied somebody else's.
    /// </remarks>
    static string ResolveAuthenticatedEmail(ClaimsPrincipal principal, out bool? emailVerified)
    {
        emailVerified = bool.TryParse(principal.FindFirst("email_verified")?.Value, out var verified)
            ? verified
            : null;

        var preferredUsername = principal.FindFirst("preferred_username")?.Value;

        return principal.FindFirst("email")?.Value
            ?? principal.FindFirst(ClaimTypes.Email)?.Value
            ?? (InviteMiddleware.IsAnEmailAddress(preferredUsername) ? preferredUsername : null)
            ?? string.Empty;
    }

    static bool TryGetSingleExactClaim(ClaimsPrincipal principal, string claimType, out string value)
    {
        var claims = principal.Claims.Where(_ => string.Equals(_.Type, claimType, StringComparison.Ordinal)).ToArray();
        if (claims.Length != 1
            || string.IsNullOrWhiteSpace(claims[0].Value)
            || claims[0].Value.Length > 2048
            || !string.Equals(claims[0].Value, claims[0].Value.Trim(), StringComparison.Ordinal))
        {
            value = string.Empty;
            return false;
        }

        value = claims[0].Value;
        return true;
    }

    static bool FixedTimeEquals(string expected, string actual) =>
        CryptographicOperations.FixedTimeEquals(Encoding.UTF8.GetBytes(expected), Encoding.UTF8.GetBytes(actual));

    async Task<InviteExchangeResult> CompleteAttestedInvitation(HttpContext context, string inviteToken, Func<Task<InvitationCompletionSession>> sessionFactory)
    {
        var invite = config.CurrentValue.Invite;
        if (invite is null
            || canonicalIdentityResolver is null
            || attestationIssuer is null
            || entryStateProtector is null
            || inviteToken.Length > MaximumAttestedInvitationTokenLength
            || !context.Request.Cookies.TryGetValue(Cookies.InvitationEntryState, out var protectedState)
            || !entryStateProtector.TryUnprotect(protectedState, out var entryState)
            || entryState.ExpiresAt <= DateTimeOffset.UtcNow
            || !FixedTimeEquals(entryState.CapabilityHash, InvitationAuthenticationState.ComputeCapabilityHash(inviteToken))
            || !TryGetSingleTokenClaim(inviteToken, JwtRegisteredClaimNames.Jti, out var invitationId)
            || !FixedTimeEquals(entryState.InvitationId, invitationId)
            || string.IsNullOrWhiteSpace(invite.TenantClaim)
            || !TryGetSingleTokenClaim(inviteToken, invite.TenantClaim, out var tenantId)
            || !FixedTimeEquals(entryState.TenantId, tenantId)
            || !InviteMiddleware.TryResolveRecipientMode(inviteToken, invite.EmailClaim, out var recipientProviderKey)
            || !ResolvedTenantMatchesWhenPresent(context, tenantId))
        {
            return InviteExchangeResult.Failed;
        }

        var session = await sessionFactory();
        if (!session.Succeeded
            || !InvitationAuthenticationState.Matches(entryState, session.Properties)
            || !TryResolveVerifiedIdentity(session, recipientProviderKey, out var identity)
            || (string.IsNullOrEmpty(recipientProviderKey)
                && EvaluateInvitedEmailBinding(inviteToken, identity.Email!, true) != InviteExchangeResult.Success)
            || !attestationIssuer.TryIssueComplete(entryState, identity, out var attestation))
        {
            return InviteExchangeResult.Failed;
        }

        using var client = httpClientFactory.CreateClient();
        using var request = new HttpRequestMessage(HttpMethod.Post, invite.ExchangeUrl);
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", attestation);
        request.Content = JsonContent.Create(new InvitationCompleteRequest(entryState.InvitationTransaction));

        try
        {
            using var response = await client.SendAsync(request, context.RequestAborted);
            if (response.StatusCode == System.Net.HttpStatusCode.Conflict)
            {
                return InviteExchangeResult.DuplicateSubject;
            }

            if (!response.IsSuccessStatusCode)
            {
                logger.InviteExchangeEndpointFailed((int)response.StatusCode);
                return InviteExchangeResult.Failed;
            }

            logger.InviteExchangedSuccessfully();
            return InviteExchangeResult.Success;
        }
        catch (Exception exception)
        {
            logger.FailedToCallInviteExchangeEndpoint(exception, invite.ExchangeUrl);
            return InviteExchangeResult.Failed;
        }
    }

    bool TryResolveVerifiedIdentity(
        InvitationCompletionSession session,
        string recipientProviderKey,
        out InvitationVerifiedIdentity identity)
    {
        identity = default!;
        var principal = session.Principal;
        if (principal is null)
        {
            return false;
        }

        var resolution = canonicalIdentityResolver!.Resolve(principal, principal.Identity?.AuthenticationType);
        if (!resolution.IsConfigured || !resolution.Succeeded || resolution.Identity is null)
        {
            return false;
        }

        var canonical = resolution.Identity;
        var providers = authConfig.CurrentValue.OidcProviders
            .Where(_ => string.Equals(_.CanonicalIdentity?.ProviderKey, canonical.ProviderKey, StringComparison.Ordinal))
            .Select(_ => _.CanonicalIdentity!)
            .Concat(authConfig.CurrentValue.OAuthProviders
                .Where(_ => string.Equals(_.CanonicalIdentity?.ProviderKey, canonical.ProviderKey, StringComparison.Ordinal))
                .Select(_ => _.CanonicalIdentity!))
            .ToArray();
        if (providers.Length != 1
            || !TryGetSingleExactClaim(principal, providers[0].AssuranceClaimType, out var assurance)
            || session.AuthenticatedAt is not { } authenticatedAt)
        {
            return false;
        }

        string? email = null;
        if (string.IsNullOrEmpty(recipientProviderKey))
        {
            if (!providers[0].InvitationCompletionEnabled
                || !TryGetSingleExactClaim(principal, providers[0].EmailClaimType, out email)
                || !InviteMiddleware.IsAnEmailAddress(email)
                || !TryGetSingleExactClaim(principal, providers[0].EmailVerifiedClaimType, out var emailVerified)
                || !bool.TryParse(emailVerified, out var verified)
                || !verified)
            {
                return false;
            }
        }
        else if (!providers[0].InvitationIdentityBindingCompletionEnabled
                 || !FixedTimeEquals(canonical.ProviderKey, recipientProviderKey))
        {
            return false;
        }

        identity = new InvitationVerifiedIdentity(
            canonical.ProviderKey,
            canonical.NormalizedIssuer,
            canonical.Subject,
            email,
            assurance,
            authenticatedAt);
        return true;
    }

    async Task<InviteExchangeResult> ExchangeInvite(string inviteToken, ClaimsPrincipal principal)
    {
        var exchangeUrl = config.CurrentValue.Invite?.ExchangeUrl;
        if (string.IsNullOrWhiteSpace(exchangeUrl))
        {
            logger.InviteExchangeUrlNotConfigured();
            return InviteExchangeResult.Failed;
        }

        var canonicalResolution = canonicalIdentityResolver?.Resolve(principal, principal.Identity?.AuthenticationType)
            ?? CanonicalIdentityResolution.SanitizedLegacy(principal);
        if (canonicalResolution.IsConfigured && (!canonicalResolution.Succeeded || canonicalResolution.Identity is null))
        {
            return InviteExchangeResult.Failed;
        }

        var subject = canonicalResolution.Identity?.Subject
            ?? principal.FindFirst("sub")?.Value
            ?? principal.FindFirst("oid")?.Value
            ?? principal.FindFirst(ClaimTypes.NameIdentifier)?.Value
            ?? principal.FindFirst("id")?.Value
            ?? string.Empty;

        var identityProvider = canonicalResolution.Identity?.ProviderKey
            ?? principal.FindFirst("iss")?.Value
            ?? principal.FindFirst("identity_provider")?.Value
            ?? principal.FindFirst("http://schemas.microsoft.com/accesscontrolservice/2010/07/claims/identityprovider")?.Value
            ?? principal.Identity?.AuthenticationType
            ?? string.Empty;

        var email = ResolveAuthenticatedEmail(principal, out var emailVerified);

        // An invitation is otherwise a pure bearer link - anyone with the URL could sign in with their
        // own account and be provisioned as the invited user. Bind the invite to its intended recipient by
        // requiring provider-supplied authenticated-session email evidence to match the invited email.
        var binding = EvaluateInvitedEmailBinding(inviteToken, email, emailVerified);
        if (binding == InviteExchangeResult.EmailUnavailable)
        {
            logger.InviteEmailUnavailable();
            return binding;
        }

        if (binding == InviteExchangeResult.EmailMismatch)
        {
            logger.InviteEmailMismatch();
            return binding;
        }

        using var client = httpClientFactory.CreateClient();
        using var request = new HttpRequestMessage(HttpMethod.Post, exchangeUrl);
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", inviteToken);

        // Forward the provider-supplied authenticated-session email evidence and any email_verified value so the
        // backend can perform its own defense-in-depth check at accept time. The value can be true, false, or null;
        // OAuth providers may not supply an independent email verification claim.
        request.Content = canonicalResolution.Identity is { } canonicalIdentity
            ? JsonContent.Create(new
            {
                subject,
                providerKey = canonicalIdentity.ProviderKey,
                issuer = canonicalIdentity.NormalizedIssuer,
                identityProvider,
                email,
                emailVerified
            })
            : JsonContent.Create(new { subject, identityProvider, email, emailVerified });

        HttpResponseMessage response;
        try
        {
            response = await client.SendAsync(request);
        }
        catch (Exception ex)
        {
            logger.FailedToCallInviteExchangeEndpoint(ex, exchangeUrl);
            return InviteExchangeResult.Failed;
        }

        if (response.StatusCode == System.Net.HttpStatusCode.Conflict)
        {
            logger.InviteSubjectAlreadyExists();
            return InviteExchangeResult.DuplicateSubject;
        }

        if (!response.IsSuccessStatusCode)
        {
            logger.InviteExchangeEndpointFailed((int)response.StatusCode);
            return InviteExchangeResult.Failed;
        }

        logger.InviteExchangedSuccessfully();
        return InviteExchangeResult.Success;
    }

    /// <summary>
    /// Evaluates the invite against the authenticated account, enforcing that the invited email (when the
    /// token carries one) matches provider-supplied authenticated-session email evidence.
    /// </summary>
    /// <param name="inviteToken">The validated invite token.</param>
    /// <param name="authenticatedEmail">The authenticating account's email.</param>
    /// <param name="emailVerified">
    /// The provider's <c>email_verified</c> value: <see langword="true"/>, <see langword="false"/>, or
    /// <see langword="null"/> when the provider supplies no independent verification claim.
    /// </param>
    /// <returns>
    /// <see cref="InviteExchangeResult.Success"/> when the invite is not bound to a specific email or the
    /// authenticated email matches it; <see cref="InviteExchangeResult.EmailUnavailable"/> when the provider
    /// supplied no address to bind against; otherwise <see cref="InviteExchangeResult.EmailMismatch"/>.
    /// </returns>
    /// <remarks>
    /// The two failures are kept apart deliberately. A provider that cannot tell us who this is and a provider
    /// that told us it is somebody else are different facts, and collapsing them reports a specific, wrong cause
    /// to an invitee whose account and address are both correct — leaving them no action that could work.
    /// </remarks>
    InviteExchangeResult EvaluateInvitedEmailBinding(string inviteToken, string authenticatedEmail, bool? emailVerified)
    {
        var emailClaim = config.CurrentValue.Invite?.EmailClaim;
        if (string.IsNullOrWhiteSpace(emailClaim)
            || !tokenValidator.TryGetClaim(inviteToken, emailClaim, out var invitedEmail)
            || string.IsNullOrWhiteSpace(invitedEmail))
        {
            // The invite does not target a specific email - there is nothing to bind against.
            return InviteExchangeResult.Success;
        }

        if (string.IsNullOrWhiteSpace(authenticatedEmail))
        {
            return InviteExchangeResult.EmailUnavailable;
        }

        // The invite is bound to a specific email, so the account must own that email and the provider
        // must not have flagged it as unverified.
        if (emailVerified == false)
        {
            return InviteExchangeResult.EmailMismatch;
        }

        return string.Equals(invitedEmail, authenticatedEmail, StringComparison.OrdinalIgnoreCase)
            ? InviteExchangeResult.Success
            : InviteExchangeResult.EmailMismatch;
    }

    bool IsTenantIssuedInvite(string inviteToken, HttpContext context)
    {
        var tenantClaim = config.CurrentValue.Invite?.TenantClaim;
        if (string.IsNullOrEmpty(tenantClaim))
        {
            return false;
        }

        if (!tokenValidator.TryGetClaim(inviteToken, tenantClaim, out var tokenTenantIdStr))
        {
            return false;
        }

        if (string.IsNullOrWhiteSpace(tokenTenantIdStr))
        {
            return false;
        }

        if (!TryResolveTenant(context, out var resolvedTenantId))
        {
            return false;
        }

        return string.Equals(tokenTenantIdStr, resolvedTenantId, StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>
    /// Resolves the tenant the current request is being served for.
    /// </summary>
    /// <param name="context">The current <see cref="HttpContext"/>.</param>
    /// <param name="tenantId">The resolved tenant when one exists.</param>
    /// <returns><see langword="true"/> when a tenant resolves for the request; otherwise <see langword="false"/>.</returns>
    /// <remarks>
    /// On the middleware path <see cref="TenancyMiddleware"/> has already resolved the tenant into
    /// <see cref="HttpContext.Items"/>. The provider callback is answered inside authentication, before that
    /// middleware runs, so the same resolver is consulted directly there — it reads the same request facts
    /// the follow-up request would have presented, so both paths answer the tenant question identically.
    /// </remarks>
    bool TryResolveTenant(HttpContext context, out string tenantId)
    {
        if (context.Items.TryGetValue(TenancyMiddleware.TenantIdItemKey, out var resolved)
            && resolved is string resolvedTenantId
            && !string.IsNullOrWhiteSpace(resolvedTenantId))
        {
            tenantId = resolvedTenantId;
            return true;
        }

        if (!context.Items.ContainsKey(TenancyMiddleware.TenantIdItemKey)
            && tenantResolver.TryResolve(context, out string directlyResolved)
            && !string.IsNullOrWhiteSpace(directlyResolved))
        {
            tenantId = directlyResolved;
            return true;
        }

        tenantId = string.Empty;
        return false;
    }

    string BuildLobbyRedirectUrlWithInvitationId(string lobbyUrl, string inviteToken)
    {
        var inviteConfig = config.CurrentValue.Invite;
        if (inviteConfig?.AppendInvitationIdToQueryString != true)
        {
            return lobbyUrl;
        }

        var queryKey = string.IsNullOrWhiteSpace(inviteConfig.InvitationIdQueryStringKey)
            ? "invitationId"
            : inviteConfig.InvitationIdQueryStringKey;

        if (!tokenValidator.TryGetClaim(inviteToken, "jti", out var invitationId)
            || string.IsNullOrWhiteSpace(invitationId))
        {
            return lobbyUrl;
        }

        var separator = lobbyUrl.Contains('?') ? '&' : '?';
        return $"{lobbyUrl}{separator}{Uri.EscapeDataString(queryKey)}={Uri.EscapeDataString(invitationId)}";
    }

    bool IsAttestedProtocolEnabled() => config.CurrentValue.Invite?.Attestation is not null;
}
