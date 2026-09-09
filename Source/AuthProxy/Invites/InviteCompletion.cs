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
        var invite = config.CurrentValue.Invite;
        var tenantRelation = ResolveInvitationTenantRelation(inviteToken, context);
        var destination = tenantRelation == InvitationTenantRelation.Matching
            ? invite?.MatchingTenantInvitationDestination ?? C.InvitationCompletionDestination.ReturnUrl
            : C.InvitationCompletionDestination.Lobby;

        if (destination == C.InvitationCompletionDestination.ReturnUrl)
        {
            logger.InvitationCompletionDestinationSelected(destination, tenantRelation);
            return false;
        }

        var lobbyUrl = invite?.Lobby?.Frontend?.BaseUrl;
        if (string.IsNullOrWhiteSpace(lobbyUrl))
        {
            return false;
        }

        lobbyRedirectUrl = BuildLobbyRedirectUrlWithInvitationId(lobbyUrl, inviteToken);
        logger.InvitationCompletionDestinationSelected(destination, tenantRelation);
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
    /// The value of the provider's <c language="text">email_verified</c> claim when present; otherwise <see langword="null"/>.
    /// </param>
    /// <returns>The authenticated email, or an empty string when none is available.</returns>
    /// <remarks>
    /// <c language="text">preferred_username</c> is a username, not an address — for a GitHub OAuth provider it is conventionally
    /// mapped from <c language="text">login</c>. It is read only when it actually holds an address, which several OIDC providers
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

    /// <summary>Logs and maps a failed verified-identity resolution to its outward exchange outcome.</summary>
    /// <param name="logger">The logger to record the failure on.</param>
    /// <param name="identityResolution">The failed <see cref="VerifiedIdentityResolution"/>.</param>
    /// <returns>The <see cref="InviteExchangeResult"/> to answer the caller with.</returns>
    static InviteExchangeResult LogAndMapIdentityFailure(ILogger logger, VerifiedIdentityResolution identityResolution)
    {
        if (identityResolution.EmailOutcome == InviteExchangeResult.EmailMismatch)
        {
            logger.InviteEmailMismatch();
            return InviteExchangeResult.EmailMismatch;
        }

        if (identityResolution.EmailOutcome == InviteExchangeResult.EmailUnavailable)
        {
            logger.InviteEmailUnavailable();
            return InviteExchangeResult.EmailUnavailable;
        }

        logger.AttestedInvitationCompletionFailed(identityResolution.Reason);
        return InviteExchangeResult.Failed;
    }

    /// <summary>Calls the invitation exchange endpoint with a freshly issued attestation.</summary>
    /// <param name="httpClientFactory">The HTTP client factory used for the exchange call.</param>
    /// <param name="logger">The logger to record the outcome on.</param>
    /// <param name="context">The current <see cref="HttpContext"/>, consulted only for its cancellation token.</param>
    /// <param name="entryResolution">The succeeded <see cref="EntryStateResolution"/> naming the exchange URL and transaction.</param>
    /// <param name="attestation">The signed attestation bearer token.</param>
    /// <returns>The outcome of the exchange call.</returns>
    static async Task<InviteExchangeResult> SendAttestedExchangeRequest(IHttpClientFactory httpClientFactory, ILogger logger, HttpContext context, EntryStateResolution entryResolution, string attestation)
    {
        using var client = httpClientFactory.CreateClient();
        using var request = new HttpRequestMessage(HttpMethod.Post, entryResolution.Invite.ExchangeUrl);
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", attestation);
        request.Content = JsonContent.Create(new InvitationCompleteRequest(entryResolution.EntryState.InvitationTransaction));

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
            logger.FailedToCallInviteExchangeEndpoint(exception, entryResolution.Invite.ExchangeUrl);
            return InviteExchangeResult.Failed;
        }
    }

    async Task<InviteExchangeResult> CompleteAttestedInvitation(HttpContext context, string inviteToken, Func<Task<InvitationCompletionSession>> sessionFactory)
    {
        var entryResolution = ResolveEntryState(context, inviteToken);
        if (!entryResolution.Succeeded)
        {
            logger.AttestedInvitationCompletionFailed(entryResolution.Reason);
            return InviteExchangeResult.Failed;
        }

        var session = await sessionFactory();
        if (!session.Succeeded)
        {
            logger.AttestedInvitationCompletionFailed(InvitationCompletionFailureReason.SessionNotEstablished);
            return InviteExchangeResult.Failed;
        }

        if (!InvitationAuthenticationState.Matches(entryResolution.EntryState, session.Properties))
        {
            logger.AttestedInvitationCompletionFailed(InvitationCompletionFailureReason.ChallengeBindingMismatch);
            return InviteExchangeResult.Failed;
        }

        var identityResolution = ResolveVerifiedIdentity(inviteToken, session, entryResolution.RecipientProviderKey);
        if (!identityResolution.Succeeded)
        {
            return LogAndMapIdentityFailure(logger, identityResolution);
        }

        if (!attestationIssuer!.TryIssueComplete(entryResolution.EntryState, identityResolution.Identity, out var attestation))
        {
            logger.AttestedInvitationCompletionFailed(InvitationCompletionFailureReason.AttestationIssuanceFailed);
            return InviteExchangeResult.Failed;
        }

        return await SendAttestedExchangeRequest(httpClientFactory, logger, context, entryResolution, attestation);
    }

    /// <summary>
    /// Same guard order as the original compound condition; split into named stages only so each one can
    /// report its own bounded reason instead of a single collapsed boolean.
    /// </summary>
    /// <param name="context">The current <see cref="HttpContext"/>.</param>
    /// <param name="inviteToken">The invitation capability presented on the request.</param>
    /// <returns>The resolved <see cref="EntryStateResolution"/>.</returns>
    EntryStateResolution ResolveEntryState(HttpContext context, string inviteToken)
    {
        var invite = config.CurrentValue.Invite;
        if (invite is null || canonicalIdentityResolver is null || attestationIssuer is null || entryStateProtector is null)
        {
            return EntryStateResolution.Failure(InvitationCompletionFailureReason.ProtocolMisconfigured);
        }

        if (inviteToken.Length > MaximumAttestedInvitationTokenLength)
        {
            return EntryStateResolution.Failure(InvitationCompletionFailureReason.CapabilityTokenTooLong);
        }

        if (!context.Request.Cookies.TryGetValue(Cookies.InvitationEntryState, out var protectedState)
            || !entryStateProtector.TryUnprotect(protectedState, out var entryState))
        {
            return EntryStateResolution.Failure(InvitationCompletionFailureReason.EntryStateUnprotectFailed);
        }

        if (entryState.ExpiresAt <= DateTimeOffset.UtcNow)
        {
            return EntryStateResolution.Failure(InvitationCompletionFailureReason.EntryStateExpired);
        }

        if (!FixedTimeEquals(entryState.CapabilityHash, InvitationAuthenticationState.ComputeCapabilityHash(inviteToken)))
        {
            return EntryStateResolution.Failure(InvitationCompletionFailureReason.CapabilityHashMismatch);
        }

        if (!TryGetSingleTokenClaim(inviteToken, JwtRegisteredClaimNames.Jti, out var invitationId))
        {
            return EntryStateResolution.Failure(InvitationCompletionFailureReason.InvitationIdClaimInvalid);
        }

        if (!FixedTimeEquals(entryState.InvitationId, invitationId))
        {
            return EntryStateResolution.Failure(InvitationCompletionFailureReason.InvitationIdMismatch);
        }

        return ResolveTenantScopedEntryState(context, invite, entryState, inviteToken);
    }

    /// <summary>
    /// Continues the entry-state guard chain once capability and invitation-id evidence have checked out,
    /// resolving the tenant-scoped facts and the recipient mode.
    /// </summary>
    /// <param name="context">The current <see cref="HttpContext"/>.</param>
    /// <param name="invite">The resolved invite configuration.</param>
    /// <param name="entryState">The unprotected invitation-entry state.</param>
    /// <param name="inviteToken">The invitation capability presented on the request.</param>
    /// <returns>The resolved <see cref="EntryStateResolution"/>.</returns>
    EntryStateResolution ResolveTenantScopedEntryState(HttpContext context, C.Invite invite, InvitationEntryState entryState, string inviteToken)
    {
        if (string.IsNullOrWhiteSpace(invite.TenantClaim))
        {
            return EntryStateResolution.Failure(InvitationCompletionFailureReason.TenantClaimNotConfigured);
        }

        if (!TryGetSingleTokenClaim(inviteToken, invite.TenantClaim, out var tenantId))
        {
            return EntryStateResolution.Failure(InvitationCompletionFailureReason.TenantClaimInvalid);
        }

        if (!FixedTimeEquals(entryState.TenantId, tenantId))
        {
            return EntryStateResolution.Failure(InvitationCompletionFailureReason.TenantIdMismatch);
        }

        if (!InviteMiddleware.TryResolveRecipientMode(inviteToken, invite.EmailClaim, out var recipientProviderKey))
        {
            return EntryStateResolution.Failure(InvitationCompletionFailureReason.RecipientModeInvalid);
        }

        if (!ResolvedTenantMatchesWhenPresent(context, tenantId))
        {
            return EntryStateResolution.Failure(InvitationCompletionFailureReason.RequestTenantMismatch);
        }

        return EntryStateResolution.Success(invite, entryState, recipientProviderKey);
    }

    /// <summary>
    /// Unlike the legacy protocol's <see cref="EvaluateInvitedEmailBinding"/> call below, a missing/duplicated/
    /// unparseable email_verified claim is never treated as acceptable here - only a single claim parsing to
    /// exactly true counts as verified; anything else is evaluated as unverified, exactly like an explicit "false".
    /// </summary>
    /// <param name="inviteToken">The invitation capability presented on the request.</param>
    /// <param name="session">The completion session carrying the authenticated principal.</param>
    /// <param name="recipientProviderKey">The identity-bound recipient's provider key, or empty for email-targeted recipients.</param>
    /// <returns>The resolved <see cref="VerifiedIdentityResolution"/>.</returns>
    VerifiedIdentityResolution ResolveVerifiedIdentity(string inviteToken, InvitationCompletionSession session, string recipientProviderKey)
    {
        var principal = session.Principal;
        if (principal is null)
        {
            return VerifiedIdentityResolution.Failure(InvitationCompletionFailureReason.PrincipalMissing);
        }

        // The scheme is asserted, never read off the principal: by this point in both call sites - a
        // re-authenticated cookie session, or a ticket about to be signed into that same cookie scheme -
        // the principal is already the once-canonicalized cookie identity, not a fresh provider callback.
        // A protocol-dependent artifact like ClaimsIdentity.AuthenticationType (OIDC's default identity
        // carries "AuthenticationTypes.Federation", never the provider's scheme name or "Cookies") must
        // never stand in for that server-owned fact, upstream Cratis/AuthProxy#122.
        var resolution = canonicalIdentityResolver!.Resolve(principal, CookieAuthenticationDefaults.AuthenticationScheme);
        if (!resolution.IsConfigured)
        {
            return VerifiedIdentityResolution.Failure(InvitationCompletionFailureReason.CanonicalIdentityNotConfigured);
        }

        if (!resolution.Succeeded || resolution.Identity is null)
        {
            return VerifiedIdentityResolution.Failure(InvitationCompletionFailureReason.CanonicalIdentityResolutionFailed);
        }

        return ResolveVerifiedIdentityForCanonical(inviteToken, principal, session, recipientProviderKey, resolution.Identity);
    }

    /// <summary>
    /// Continues verified-identity resolution once the canonical identity itself has resolved: locates the
    /// single configured provider matching its provider key, then resolves the recipient-mode-specific facts.
    /// </summary>
    /// <param name="inviteToken">The invitation capability presented on the request.</param>
    /// <param name="principal">The authenticated principal.</param>
    /// <param name="session">The completion session carrying the authentication-time evidence.</param>
    /// <param name="recipientProviderKey">The identity-bound recipient's provider key, or empty for email-targeted recipients.</param>
    /// <param name="canonical">The resolved canonical federated identity.</param>
    /// <returns>The resolved <see cref="VerifiedIdentityResolution"/>.</returns>
    VerifiedIdentityResolution ResolveVerifiedIdentityForCanonical(
        string inviteToken, ClaimsPrincipal principal, InvitationCompletionSession session, string recipientProviderKey, CanonicalFederatedIdentity canonical)
    {
        var providers = authConfig.CurrentValue.OidcProviders
            .Where(_ => string.Equals(_.CanonicalIdentity?.ProviderKey, canonical.ProviderKey, StringComparison.Ordinal))
            .Select(_ => _.CanonicalIdentity!)
            .Concat(authConfig.CurrentValue.OAuthProviders
                .Where(_ => string.Equals(_.CanonicalIdentity?.ProviderKey, canonical.ProviderKey, StringComparison.Ordinal))
                .Select(_ => _.CanonicalIdentity!))
            .ToArray();
        if (providers.Length != 1)
        {
            return VerifiedIdentityResolution.Failure(InvitationCompletionFailureReason.ProviderConfigurationAmbiguous);
        }

        var provider = providers[0];
        if (!TryGetSingleExactClaim(principal, provider.AssuranceClaimType, out var assurance)
            || session.AuthenticatedAt is not { } authenticatedAt)
        {
            return VerifiedIdentityResolution.Failure(InvitationCompletionFailureReason.AssuranceEvidenceUnavailable);
        }

        if (string.IsNullOrEmpty(recipientProviderKey))
        {
            return ResolveEmailTargetedIdentity(inviteToken, principal, provider, canonical, assurance, authenticatedAt);
        }

        if (!provider.InvitationIdentityBindingCompletionEnabled)
        {
            return VerifiedIdentityResolution.Failure(InvitationCompletionFailureReason.IdentityBindingCompletionDisabled);
        }

        if (!FixedTimeEquals(canonical.ProviderKey, recipientProviderKey))
        {
            return VerifiedIdentityResolution.Failure(InvitationCompletionFailureReason.IdentityBindingProviderMismatch);
        }

        return VerifiedIdentityResolution.Success(new InvitationVerifiedIdentity(
            canonical.ProviderKey, canonical.NormalizedIssuer, canonical.Subject, null, assurance, authenticatedAt));
    }

    /// <summary>
    /// Resolves an email-targeted recipient's verified identity, enforcing the strict single-explicit-true
    /// email_verified claim requirement described on <see cref="ResolveVerifiedIdentity"/>.
    /// </summary>
    /// <param name="inviteToken">The invitation capability presented on the request.</param>
    /// <param name="principal">The authenticated principal.</param>
    /// <param name="provider">The single configured canonical identity provider matching the resolved provider key.</param>
    /// <param name="canonical">The resolved canonical federated identity.</param>
    /// <param name="assurance">The provider-supplied authentication assurance evidence.</param>
    /// <param name="authenticatedAt">The session's authentication-time evidence.</param>
    /// <returns>The resolved <see cref="VerifiedIdentityResolution"/>.</returns>
    VerifiedIdentityResolution ResolveEmailTargetedIdentity(
        string inviteToken, ClaimsPrincipal principal, C.CanonicalIdentity provider, CanonicalFederatedIdentity canonical, string assurance, DateTimeOffset authenticatedAt)
    {
        if (!provider.InvitationCompletionEnabled)
        {
            return VerifiedIdentityResolution.Failure(InvitationCompletionFailureReason.EmailCompletionDisabledForProvider);
        }

        TryGetSingleExactClaim(principal, provider.EmailClaimType, out var rawEmail);
        var email = InviteMiddleware.IsAnEmailAddress(rawEmail) ? rawEmail : string.Empty;
        var emailVerified = TryGetSingleExactClaim(principal, provider.EmailVerifiedClaimType, out var rawEmailVerified)
            && bool.TryParse(rawEmailVerified, out var parsedEmailVerified)
            && parsedEmailVerified;

        var binding = EvaluateInvitedEmailBinding(inviteToken, email, emailVerified);
        if (binding != InviteExchangeResult.Success)
        {
            return VerifiedIdentityResolution.EmailFailure(binding);
        }

        return VerifiedIdentityResolution.Success(new InvitationVerifiedIdentity(
            canonical.ProviderKey, canonical.NormalizedIssuer, canonical.Subject, email, assurance, authenticatedAt));
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
    /// The provider's <c language="text">email_verified</c> value: <see langword="true"/>, <see langword="false"/>, or
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

    /// <summary>
    /// Resolves the observed relation between the invitation's configured tenant claim and the tenant resolved
    /// for the request.
    /// </summary>
    /// <param name="inviteToken">The validated invitation capability.</param>
    /// <param name="context">The current <see cref="HttpContext"/>.</param>
    /// <returns>The observed tenant relation.</returns>
    /// <remarks>
    /// Equality is observational routing evidence, not issuer identity. Any issuer holding the signing key can
    /// write the tenant claim. A match proves only that the invitation names the tenant serving the request.
    /// </remarks>
    InvitationTenantRelation ResolveInvitationTenantRelation(string inviteToken, HttpContext context)
    {
        var tenantClaim = config.CurrentValue.Invite?.TenantClaim;
        if (string.IsNullOrEmpty(tenantClaim)
            || !tokenValidator.TryGetClaim(inviteToken, tenantClaim, out var tokenTenantId)
            || string.IsNullOrWhiteSpace(tokenTenantId)
            || !TryResolveTenant(context, out var resolvedTenantId))
        {
            return InvitationTenantRelation.Unresolved;
        }

        return string.Equals(tokenTenantId, resolvedTenantId, StringComparison.OrdinalIgnoreCase)
            ? InvitationTenantRelation.Matching
            : InvitationTenantRelation.NonMatching;
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

    /// <summary>An attested invitation's pre-HTTP entry-state resolution.</summary>
    /// <param name="Succeeded"><see langword="true"/> when the entry state resolved.</param>
    /// <param name="Invite">The resolved invite configuration.</param>
    /// <param name="EntryState">The unprotected invitation-entry state.</param>
    /// <param name="RecipientProviderKey">The identity-bound recipient's provider key, or empty for email-targeted recipients.</param>
    /// <param name="Reason">The bounded failure reason, or <see cref="InvitationCompletionFailureReason.None"/> on success.</param>
    readonly record struct EntryStateResolution(bool Succeeded, C.Invite Invite, InvitationEntryState EntryState, string RecipientProviderKey, InvitationCompletionFailureReason Reason)
    {
        public static EntryStateResolution Success(C.Invite invite, InvitationEntryState entryState, string recipientProviderKey) =>
            new(Succeeded: true, Invite: invite, EntryState: entryState, RecipientProviderKey: recipientProviderKey, Reason: InvitationCompletionFailureReason.None);

        public static EntryStateResolution Failure(InvitationCompletionFailureReason reason) =>
            new(Succeeded: false, Invite: default!, EntryState: default!, RecipientProviderKey: string.Empty, Reason: reason);
    }

    /// <summary>
    /// An attested invitation's verified-identity resolution. A failure carries either a bounded reason, or
    /// - for the email-targeted recipient mode - the specific <see cref="InviteExchangeResult.EmailMismatch"/>/
    /// <see cref="InviteExchangeResult.EmailUnavailable"/> outcome.
    /// </summary>
    /// <param name="Succeeded"><see langword="true"/> when a verified identity resolved.</param>
    /// <param name="Identity">The resolved verified identity.</param>
    /// <param name="EmailOutcome">The specific email-binding outcome for the email-targeted recipient mode.</param>
    /// <param name="Reason">The bounded failure reason, or <see cref="InvitationCompletionFailureReason.None"/> on success.</param>
    readonly record struct VerifiedIdentityResolution(bool Succeeded, InvitationVerifiedIdentity Identity, InviteExchangeResult EmailOutcome, InvitationCompletionFailureReason Reason)
    {
        public static VerifiedIdentityResolution Success(InvitationVerifiedIdentity identity) =>
            new(Succeeded: true, Identity: identity, EmailOutcome: InviteExchangeResult.Success, Reason: InvitationCompletionFailureReason.None);

        public static VerifiedIdentityResolution EmailFailure(InviteExchangeResult outcome) =>
            new(Succeeded: false, Identity: default!, EmailOutcome: outcome, Reason: InvitationCompletionFailureReason.None);

        public static VerifiedIdentityResolution Failure(InvitationCompletionFailureReason reason) =>
            new(Succeeded: false, Identity: default!, EmailOutcome: InviteExchangeResult.Failed, Reason: reason);
    }
}
