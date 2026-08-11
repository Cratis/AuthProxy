// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Diagnostics.CodeAnalysis;
using System.Net.Http.Headers;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using Cratis.AuthProxy.Authentication;
using Cratis.AuthProxy.ErrorPages;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using C = Cratis.AuthProxy.Configuration;

namespace Cratis.AuthProxy.Invites;

/// <summary>
/// Middleware that implements the two-phase invite flow:
/// <list type="number">
///   <item>
///     Handles <c>/invite/{token}</c> – validates the token, stores it in a short-lived
///     HTTP-only cookie and redirects the user to the OIDC login.
///     If multiple identity providers are configured the invitation provider-selection page
///     is served so the user can choose which provider to use.
///     If the token is expired the <c>invitation-expired.html</c> error page is returned.
///     If the token is malformed or has an invalid signature the <c>invitation-invalid.html</c> page is returned.
///   </item>
///   <item>
///     After a successful OIDC login – detects the pending invite cookie, calls the Lobby invitation authority's
///     completion endpoint, deletes the cookie, and signals any required lobby redirect via
///     <see cref="LobbyRedirectUrlItemKey"/> in <see cref="HttpContext.Items"/> before
///     continuing the pipeline. Identity resolution and the actual redirect are handled by
///     <see cref="Identity.IdentityMiddleware"/> and <see cref="InviteRedirectMiddleware"/>
///     respectively.
///   </item>
/// </list>
/// </summary>
/// <param name="next">The next middleware in the pipeline.</param>
/// <param name="tokenValidator">The validator for invite JWT tokens.</param>
/// <param name="config">The auth proxy configuration monitor.</param>
/// <param name="authConfig">The authentication configuration monitor, used to determine how many providers are available.</param>
/// <param name="tenantResolver">The tenant resolver used to capture tenant metadata in authentication state.</param>
/// <param name="httpClientFactory">The HTTP client factory used for the exchange call.</param>
/// <param name="errorPageProvider">The error page provider used to serve custom error pages.</param>
/// <param name="logger">The logger.</param>
/// <param name="canonicalIdentityResolver">The shared canonical identity resolver, or <see langword="null"/> for legacy-compatible direct construction.</param>
/// <param name="attestationIssuer">The signed invitation-attestation issuer, or <see langword="null"/> for legacy-compatible direct construction.</param>
/// <param name="entryStateProtector">The protected invitation-entry state service, or <see langword="null"/> for legacy-compatible direct construction.</param>
public class InviteMiddleware(
    RequestDelegate next,
    IInviteTokenValidator tokenValidator,
    IOptionsMonitor<C.AuthProxy> config,
    IOptionsMonitor<C.Authentication> authConfig,
    ITenantResolver tenantResolver,
    IHttpClientFactory httpClientFactory,
    IErrorPageProvider errorPageProvider,
    ILogger<InviteMiddleware> logger,
    ICanonicalIdentityResolver? canonicalIdentityResolver,
    IInvitationAttestationIssuer? attestationIssuer,
    IInvitationEntryStateProtector? entryStateProtector)
{
    /// <summary>The route prefix that triggers invite handling.</summary>
    public const string InvitePathPrefix = WellKnownPaths.InvitePathPrefix;

    /// <summary>
    /// Key used to store the post-exchange lobby redirect URL in <see cref="HttpContext.Items"/>.
    /// Set by Phase 2 when exchange succeeds and the invite is not tenant-issued.
    /// Read by <see cref="InviteRedirectMiddleware"/> to perform the actual redirect.
    /// </summary>
    public const string LobbyRedirectUrlItemKey = "Cratis.InviteLobbyRedirectUrl";

    const int MaximumAttestedInvitationTokenLength = 4096;

    static readonly JsonSerializerOptions _providerSerializerOptions = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        Converters = { new JsonStringEnumConverter() }
    };

    /// <summary>
    /// Initializes a legacy-compatible instance that sanitizes reserved canonical claims without resolving canonical providers.
    /// </summary>
    /// <param name="next">The next middleware in the pipeline.</param>
    /// <param name="tokenValidator">The validator for invite JWT tokens.</param>
    /// <param name="config">The auth proxy configuration monitor.</param>
    /// <param name="authConfig">The authentication configuration monitor.</param>
    /// <param name="tenantResolver">The tenant resolver used to capture tenant metadata in authentication state.</param>
    /// <param name="httpClientFactory">The HTTP client factory used for the exchange call.</param>
    /// <param name="errorPageProvider">The error page provider used to serve custom error pages.</param>
    /// <param name="logger">The logger.</param>
    public InviteMiddleware(
        RequestDelegate next,
        IInviteTokenValidator tokenValidator,
        IOptionsMonitor<C.AuthProxy> config,
        IOptionsMonitor<C.Authentication> authConfig,
        ITenantResolver tenantResolver,
        IHttpClientFactory httpClientFactory,
        IErrorPageProvider errorPageProvider,
        ILogger<InviteMiddleware> logger)
        : this(next, tokenValidator, config, authConfig, tenantResolver, httpClientFactory, errorPageProvider, logger, null, null, null)
    {
    }

    /// <summary>
    /// Initializes a resolver-aware instance preserving the previously released constructor contract.
    /// </summary>
    /// <param name="next">The next middleware in the pipeline.</param>
    /// <param name="tokenValidator">The validator for invite JWT tokens.</param>
    /// <param name="config">The auth proxy configuration monitor.</param>
    /// <param name="authConfig">The authentication configuration monitor.</param>
    /// <param name="tenantResolver">The tenant resolver used to capture tenant metadata in authentication state.</param>
    /// <param name="httpClientFactory">The HTTP client factory used for the exchange call.</param>
    /// <param name="errorPageProvider">The error page provider used to serve custom error pages.</param>
    /// <param name="logger">The logger.</param>
    /// <param name="canonicalIdentityResolver">The canonical identity resolver.</param>
    public InviteMiddleware(
        RequestDelegate next,
        IInviteTokenValidator tokenValidator,
        IOptionsMonitor<C.AuthProxy> config,
        IOptionsMonitor<C.Authentication> authConfig,
        ITenantResolver tenantResolver,
        IHttpClientFactory httpClientFactory,
        IErrorPageProvider errorPageProvider,
        ILogger<InviteMiddleware> logger,
        ICanonicalIdentityResolver? canonicalIdentityResolver)
        : this(next, tokenValidator, config, authConfig, tenantResolver, httpClientFactory, errorPageProvider, logger, canonicalIdentityResolver, null, null)
    {
    }

    /// <inheritdoc cref="IMiddleware.InvokeAsync"/>
    public async Task InvokeAsync(HttpContext context)
    {
        // ── Phase 2: post-login invite exchange ───────────────────────────────
        // Run this first so authenticated callbacks that return to /invite/{token}
        // do not get re-challenged and end up in a redirect loop.
        if (context.User.Identity?.IsAuthenticated == true
            && context.TryGetPendingInvitationToken(out var inviteToken))
        {
            // Re-validate the invite token before forwarding it (Phase 2). The token arrives from the
            // HTTP-only .cratis-invite cookie, but HTTP-only only blocks browser JS - an authenticated
            // caller can still set the cookie to a self-crafted token. AuthProxy must therefore be the
            // authoritative invite-token validator across BOTH phases, re-checking the RSA signature,
            // issuer, audience and lifetime here before handing the token to the exchange endpoint.
            var validationResult = tokenValidator.ValidateDetailed(inviteToken);
            if (validationResult != InviteTokenValidationResult.Valid)
            {
                logger.InviteExchangeTokenValidationFailed(validationResult);
                context.Response.Cookies.Delete(Cookies.InviteToken);
                context.Response.Cookies.Delete(Cookies.InvitationEntryState);
                context.Response.Cookies.Delete(Cookies.InviteToken, new CookieOptions { Path = "/" });
                context.Response.Cookies.Delete(Cookies.InvitationEntryState, new CookieOptions { Path = "/" });

                var invalidPageName = validationResult == InviteTokenValidationResult.Expired
                    ? WellKnownPageNames.InvitationExpired
                    : WellKnownPageNames.InvitationInvalid;

                await errorPageProvider.WriteErrorPageAsync(
                    context,
                    invalidPageName,
                    StatusCodes.Status401Unauthorized);
                return;
            }

            var exchangeResult = IsAttestedProtocolEnabled()
                ? await CompleteAttestedInvitation(context, inviteToken)
                : await ExchangeInvite(context, inviteToken);
            context.Response.Cookies.Delete(Cookies.InviteToken);
            context.Response.Cookies.Delete(Cookies.InvitationEntryState);
            context.Response.Cookies.Delete(Cookies.InviteToken, new CookieOptions { Path = "/" });
            context.Response.Cookies.Delete(Cookies.InvitationEntryState, new CookieOptions { Path = "/" });

            if (exchangeResult == InviteExchangeResult.EmailMismatch)
            {
                await errorPageProvider.WriteErrorPageAsync(
                    context,
                    WellKnownPageNames.InvitationEmailMismatch,
                    StatusCodes.Status403Forbidden);

                return;
            }

            if (exchangeResult == InviteExchangeResult.EmailUnavailable)
            {
                await errorPageProvider.WriteErrorPageAsync(
                    context,
                    WellKnownPageNames.InvitationEmailUnavailable,
                    StatusCodes.Status403Forbidden);

                return;
            }

            if (exchangeResult == InviteExchangeResult.DuplicateSubject)
            {
                var subjectAlreadyExistsUrl = config.CurrentValue.Invite?.SubjectAlreadyExistsUrl;
                if (!string.IsNullOrWhiteSpace(subjectAlreadyExistsUrl))
                {
                    context.Response.Redirect(subjectAlreadyExistsUrl);
                }
                else
                {
                    await errorPageProvider.WriteErrorPageAsync(
                        context,
                        WellKnownPageNames.InvitationSubjectAlreadyExists,
                        StatusCodes.Status409Conflict);
                }

                return;
            }

            if (exchangeResult == InviteExchangeResult.Failed && IsAttestedProtocolEnabled())
            {
                await errorPageProvider.WriteErrorPageAsync(
                    context,
                    WellKnownPageNames.InvitationInvalid,
                    StatusCodes.Status403Forbidden);
                return;
            }

            if (exchangeResult == InviteExchangeResult.Success && !IsTenantIssuedInvite(inviteToken, context))
            {
                var lobbyUrl = config.CurrentValue.Invite?.Lobby?.Frontend?.BaseUrl;
                if (!string.IsNullOrWhiteSpace(lobbyUrl))
                {
                    context.Items[LobbyRedirectUrlItemKey] = BuildLobbyRedirectUrlWithInvitationId(lobbyUrl, inviteToken);
                }
            }

            await next(context);
            return;
        }

        // ── Phase 1: incoming invite URL ──────────────────────────────────────
        if (context.TryGetInvitationToken(out var token))
        {
            if (string.IsNullOrEmpty(token))
            {
                context.Response.StatusCode = StatusCodes.Status400BadRequest;
                return;
            }

            var validationResult = tokenValidator.ValidateDetailed(token);
            if (validationResult != InviteTokenValidationResult.Valid)
            {
                logger.InviteTokenValidationFailed(validationResult);

                var pageName = validationResult == InviteTokenValidationResult.Expired
                    ? WellKnownPageNames.InvitationExpired
                    : WellKnownPageNames.InvitationInvalid;

                await errorPageProvider.WriteErrorPageAsync(
                    context,
                    pageName,
                    StatusCodes.Status401Unauthorized);
                return;
            }

            var attestedProtocolEnabled = IsAttestedProtocolEnabled();
            var recipientProviderKey = string.Empty;
            if (attestedProtocolEnabled
                && !TryResolveRecipientMode(
                    token,
                    config.CurrentValue.Invite?.EmailClaim,
                    out recipientProviderKey))
            {
                await errorPageProvider.WriteErrorPageAsync(
                    context,
                    WellKnownPageNames.InvitationInvalid,
                    StatusCodes.Status401Unauthorized);
                return;
            }

            var currentAuthConfig = authConfig.CurrentValue;
            var providers = GetAllProviders(currentAuthConfig, attestedProtocolEnabled, recipientProviderKey).ToList();
            if (attestedProtocolEnabled && providers.Count == 0)
            {
                await errorPageProvider.WriteErrorPageAsync(
                    context,
                    WellKnownPageNames.InvitationInvalid,
                    StatusCodes.Status403Forbidden);
                return;
            }

            InvitationEntryState? entryState = null;
            if (attestedProtocolEnabled)
            {
                var staging = await StageInvitation(context, token);
                if (!staging.Succeeded)
                {
                    await errorPageProvider.WriteErrorPageAsync(
                        context,
                        WellKnownPageNames.InvitationInvalid,
                        StatusCodes.Status401Unauthorized);
                    return;
                }

                entryState = staging.State;
            }

            // Store the invite token in a short-lived, HTTP-only cookie.
            context.Response.Cookies.Append(Cookies.InviteToken, token, new CookieOptions
            {
                HttpOnly = true,
                SameSite = SameSiteMode.Lax,
                Secure = context.Request.IsHttps,
                Path = "/",
                MaxAge = TimeSpan.FromMinutes(15),
            });

            if (entryState is not null)
            {
                context.Response.Cookies.Append(Cookies.InvitationEntryState, entryStateProtector!.Protect(entryState), new CookieOptions
                {
                    HttpOnly = true,
                    SameSite = SameSiteMode.Lax,
                    Secure = context.Request.IsHttps,
                    Path = "/",
                    MaxAge = TimeSpan.FromMinutes(15),
                });
            }

            if (providers.Count > 1)
            {
                // Multiple providers: inject the providers cookie and serve the selection page.
                var providersJson = JsonSerializer.Serialize(providers, _providerSerializerOptions);
                context.Response.Cookies.Append(Cookies.Providers, providersJson, new CookieOptions
                {
                    HttpOnly = false,
                    SameSite = SameSiteMode.Lax,
                    Secure = context.Request.IsHttps,
                    MaxAge = TimeSpan.FromMinutes(15),
                });

                // A sign-in page rendered inside somebody's frame is clickjacking bait — selection pages
                // are never embeddable.
                FrameEmbedding.Deny(context);
                await errorPageProvider.WriteErrorPageAsync(
                    context,
                    WellKnownPageNames.InvitationSelectProvider,
                    StatusCodes.Status200OK);
                return;
            }

            // Single provider: trigger OIDC login directly for that provider.
            // No providers: would require error handling (skipped for now).
            if (providers.Count == 1)
            {
                var scheme = OidcProviderScheme.FromName(providers[0].Name);
                var returnUrl = context.GetPathAndQuery();
                var properties = TenantAuthenticationState.CreateChallengeProperties(context, tenantResolver, returnUrl);
                if (entryState is not null)
                {
                    InvitationAuthenticationState.Bind(properties, entryState);
                }
                else if (!InvitationAuthenticationState.TryBindPendingInvitation(context, properties))
                {
                    await errorPageProvider.WriteErrorPageAsync(
                        context,
                        WellKnownPageNames.InvitationInvalid,
                        StatusCodes.Status401Unauthorized);
                    return;
                }
                await context.ChallengeAsync(scheme, properties);
                return;
            }

            // No providers configured - let Phase 2 or later middleware handle it.
            await next(context);
            return;
        }

        await next(context);
    }

    /// <summary>
    /// Resolves the one recipient-authority mode carried by a signed invitation capability.
    /// </summary>
    /// <param name="token">The already signature-validated invitation capability.</param>
    /// <param name="emailClaimType">The configured invited-email claim type.</param>
    /// <param name="recipientProviderKey">The immutable-binding provider key, or an empty value for email mode.</param>
    /// <returns>
    /// <see langword="true"/> only when the capability contains exactly one nonempty invited email or exactly one
    /// canonical provider-and-binding pair, but never both.
    /// </returns>
    internal static bool TryResolveRecipientMode(
        string token,
        string? emailClaimType,
        out string recipientProviderKey)
    {
        recipientProviderKey = string.Empty;
        if (string.IsNullOrWhiteSpace(emailClaimType))
        {
            return false;
        }

        try
        {
            var claims = new JsonWebTokenHandler().ReadJsonWebToken(token).Claims.ToArray();
            var emailClaims = claims
                .Where(_ => string.Equals(_.Type, emailClaimType, StringComparison.Ordinal))
                .ToArray();
            var providerClaims = claims
                .Where(_ => string.Equals(_.Type, InvitationCapabilityClaims.RecipientProviderKey, StringComparison.Ordinal))
                .ToArray();
            var bindingClaims = claims
                .Where(_ => string.Equals(_.Type, InvitationCapabilityClaims.RecipientIdentityBinding, StringComparison.Ordinal))
                .ToArray();
            var hasValidEmailMode = emailClaims.Length == 1
                && emailClaims[0].Value.Length <= 320
                && string.Equals(emailClaims[0].Value, emailClaims[0].Value.Trim(), StringComparison.Ordinal)
                && IsAnEmailAddress(emailClaims[0].Value)
                && providerClaims.Length == 0
                && bindingClaims.Length == 0;
            var hasValidIdentityBindingMode = emailClaims.Length == 0
                && providerClaims.Length == 1
                && bindingClaims.Length == 1
                && IsCanonicalProviderKey(providerClaims[0].Value)
                && IsCanonicalIdentityBinding(bindingClaims[0].Value);
            if (!hasValidEmailMode && !hasValidIdentityBindingMode)
            {
                return false;
            }

            if (hasValidIdentityBindingMode)
            {
                recipientProviderKey = providerClaims[0].Value;
            }
            return true;
        }
        catch (ArgumentException)
        {
            return false;
        }
    }

    /// <summary>
    /// Aggregates all configured OIDC and OAuth providers into a single enumerable of <see cref="OidcProviderInfo"/>.
    /// </summary>
    /// <param name="config">The authentication configuration containing the provider lists.</param>
    /// <param name="requireInvitationEvidence">Whether providers must be explicitly eligible for signed invitation completion.</param>
    /// <param name="recipientProviderKey">The exact provider key required by an identity-bound invitation, or an empty string for email-targeted completion.</param>
    /// <returns>An enumerable of <see cref="OidcProviderInfo"/> for every configured provider.</returns>
    static IEnumerable<OidcProviderInfo> GetAllProviders(
        C.Authentication config,
        bool requireInvitationEvidence,
        string recipientProviderKey) =>
        config.OidcProviders
            .Where(_ => IsProviderEligible(_.CanonicalIdentity, requireInvitationEvidence, recipientProviderKey))
            .Select(OidcProviderScheme.ToProviderInfo)
            .Concat(config.OAuthProviders
                .Where(_ => IsProviderEligible(_.CanonicalIdentity, requireInvitationEvidence, recipientProviderKey))
                .Select(OidcProviderScheme.ToProviderInfo));

    static bool IsProviderEligible(
        C.CanonicalIdentity? identity,
        bool requireInvitationEvidence,
        string recipientProviderKey)
    {
        if (!requireInvitationEvidence)
        {
            return true;
        }

        if (identity is null)
        {
            return false;
        }

        return string.IsNullOrEmpty(recipientProviderKey)
            ? identity.InvitationCompletionEnabled
            : identity.InvitationIdentityBindingCompletionEnabled
              && string.Equals(identity.ProviderKey, recipientProviderKey, StringComparison.Ordinal);
    }

    /// <summary>
    /// Resolves the authenticating account's email and its provider-supplied verification status.
    /// </summary>
    /// <param name="context">The current <see cref="HttpContext"/>.</param>
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
    static string ResolveAuthenticatedEmail(HttpContext context, out bool? emailVerified)
    {
        emailVerified = bool.TryParse(context.User.FindFirst("email_verified")?.Value, out var verified)
            ? verified
            : null;

        var preferredUsername = context.User.FindFirst("preferred_username")?.Value;

        return context.User.FindFirst("email")?.Value
            ?? context.User.FindFirst(ClaimTypes.Email)?.Value
            ?? (IsAnEmailAddress(preferredUsername) ? preferredUsername : null)
            ?? string.Empty;
    }

    /// <summary>
    /// Determines whether a claim value is an email address rather than a username.
    /// </summary>
    /// <param name="value">The claim value to check.</param>
    /// <returns><see langword="true"/> when the value carries a local part and a domain; otherwise <see langword="false"/>.</returns>
    static bool IsAnEmailAddress([NotNullWhen(true)] string? value)
    {
        var at = value?.IndexOf('@', StringComparison.Ordinal) ?? -1;
        return at > 0 && at < value!.Length - 1;
    }

    static bool IsCanonicalProviderKey(string value) =>
        value.Length is >= 1 and <= 64
        && value[0] is (>= 'a' and <= 'z') or (>= '0' and <= '9')
        && value.All(character => character is (>= 'a' and <= 'z') or (>= '0' and <= '9') or '.' or '_' or '-');

    static bool IsCanonicalIdentityBinding(string value)
    {
        if (value.Length != 43)
        {
            return false;
        }

        try
        {
            var bytes = WebEncoders.Base64UrlDecode(value);
            return bytes.Length == SHA256.HashSizeInBytes
                   && FixedTimeEquals(value, WebEncoders.Base64UrlEncode(bytes));
        }
        catch (FormatException)
        {
            return false;
        }
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

    static bool TryGetSingleTokenClaim(string token, string claimType, out string value)
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

    static string ComputeCapabilityHash(string inviteToken) =>
        Base64UrlEncoder.Encode(SHA256.HashData(Encoding.UTF8.GetBytes(inviteToken)));

    static bool ResolvedTenantMatchesWhenPresent(HttpContext context, string tenantId) =>
        !context.Items.TryGetValue(TenancyMiddleware.TenantIdItemKey, out var resolved)
        || resolved is not string resolvedTenantId
        || string.IsNullOrWhiteSpace(resolvedTenantId)
        || FixedTimeEquals(tenantId, resolvedTenantId);

    static bool FixedTimeEquals(string expected, string actual) =>
        CryptographicOperations.FixedTimeEquals(Encoding.UTF8.GetBytes(expected), Encoding.UTF8.GetBytes(actual));

    bool IsAttestedProtocolEnabled() => config.CurrentValue.Invite?.Attestation is not null;

    async Task<(bool Succeeded, InvitationEntryState? State)> StageInvitation(HttpContext context, string inviteToken)
    {
        var invite = config.CurrentValue.Invite;
        if (invite is null
            || attestationIssuer is null
            || entryStateProtector is null
            || inviteToken.Length > MaximumAttestedInvitationTokenLength
            || string.IsNullOrWhiteSpace(invite.StageUrl)
            || string.IsNullOrWhiteSpace(invite.TenantClaim)
            || !TryGetSingleTokenClaim(inviteToken, JwtRegisteredClaimNames.Jti, out var invitationId)
            || !TryGetSingleTokenClaim(inviteToken, invite.TenantClaim, out var tenantId)
            || !ResolvedTenantMatchesWhenPresent(context, tenantId))
        {
            return (false, null);
        }

        var entryState = new InvitationEntryState(
            tenantId,
            invitationId,
            InvitationAttestationIssuer.CreateOpaqueValue(),
            InvitationAttestationIssuer.CreateOpaqueValue(),
            ComputeCapabilityHash(inviteToken),
            DateTimeOffset.UtcNow.AddMinutes(15));
        if (!attestationIssuer.TryIssueStage(entryState, out var attestation))
        {
            return (false, null);
        }

        using var client = httpClientFactory.CreateClient();
        using var request = new HttpRequestMessage(HttpMethod.Post, invite.StageUrl);
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", attestation);
        request.Content = JsonContent.Create(new InvitationStageRequest(
            entryState.InvitationTransaction,
            inviteToken,
            entryState.InvitationChallenge));

        try
        {
            using var response = await client.SendAsync(request, context.RequestAborted);
            if (response.IsSuccessStatusCode)
            {
                return (true, entryState);
            }

            logger.InviteExchangeEndpointFailed((int)response.StatusCode);
        }
        catch (Exception exception)
        {
            logger.FailedToCallInviteExchangeEndpoint(exception, invite.StageUrl);
        }

        return (false, null);
    }

    async Task<InviteExchangeResult> CompleteAttestedInvitation(HttpContext context, string inviteToken)
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
            || !FixedTimeEquals(entryState.CapabilityHash, ComputeCapabilityHash(inviteToken))
            || !TryGetSingleTokenClaim(inviteToken, JwtRegisteredClaimNames.Jti, out var invitationId)
            || !FixedTimeEquals(entryState.InvitationId, invitationId)
            || string.IsNullOrWhiteSpace(invite.TenantClaim)
            || !TryGetSingleTokenClaim(inviteToken, invite.TenantClaim, out var tenantId)
            || !FixedTimeEquals(entryState.TenantId, tenantId)
            || !TryResolveRecipientMode(inviteToken, invite.EmailClaim, out var recipientProviderKey)
            || !ResolvedTenantMatchesWhenPresent(context, tenantId))
        {
            return InviteExchangeResult.Failed;
        }

        var authentication = await context.AuthenticateAsync(CookieAuthenticationDefaults.AuthenticationScheme);
        if (!authentication.Succeeded
            || !InvitationAuthenticationState.Matches(entryState, authentication.Properties)
            || !TryResolveVerifiedIdentity(authentication, recipientProviderKey, out var identity)
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
        AuthenticateResult authentication,
        string recipientProviderKey,
        out InvitationVerifiedIdentity identity)
    {
        identity = default!;
        var principal = authentication.Principal;
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
            || authentication.Properties?.IssuedUtc is not { } authenticatedAt)
        {
            return false;
        }

        string? email = null;
        if (string.IsNullOrEmpty(recipientProviderKey))
        {
            if (!providers[0].InvitationCompletionEnabled
                || !TryGetSingleExactClaim(principal, providers[0].EmailClaimType, out email)
                || !IsAnEmailAddress(email)
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

    async Task<InviteExchangeResult> ExchangeInvite(HttpContext context, string inviteToken)
    {
        var exchangeUrl = config.CurrentValue.Invite?.ExchangeUrl;
        if (string.IsNullOrWhiteSpace(exchangeUrl))
        {
            logger.InviteExchangeUrlNotConfigured();
            return InviteExchangeResult.Failed;
        }

        var canonicalResolution = canonicalIdentityResolver?.Resolve(context.User, context.User.Identity?.AuthenticationType)
            ?? CanonicalIdentityResolution.SanitizedLegacy(context.User);
        if (canonicalResolution.IsConfigured && (!canonicalResolution.Succeeded || canonicalResolution.Identity is null))
        {
            return InviteExchangeResult.Failed;
        }

        var subject = canonicalResolution.Identity?.Subject
            ?? context.User.FindFirst("sub")?.Value
            ?? context.User.FindFirst("oid")?.Value
            ?? context.User.FindFirst(ClaimTypes.NameIdentifier)?.Value
            ?? context.User.FindFirst("id")?.Value
            ?? string.Empty;

        var identityProvider = canonicalResolution.Identity?.ProviderKey
            ?? context.User.FindFirst("iss")?.Value
            ?? context.User.FindFirst("identity_provider")?.Value
            ?? context.User.FindFirst("http://schemas.microsoft.com/accesscontrolservice/2010/07/claims/identityprovider")?.Value
            ?? context.User.Identity?.AuthenticationType
            ?? string.Empty;

        var email = ResolveAuthenticatedEmail(context, out var emailVerified);

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

        if (!context.Items.TryGetValue(TenancyMiddleware.TenantIdItemKey, out var resolvedTenantObj)
            || resolvedTenantObj is not string resolvedTenantId
            || string.IsNullOrWhiteSpace(resolvedTenantId))
        {
            return false;
        }

        return string.Equals(tokenTenantIdStr, resolvedTenantId, StringComparison.OrdinalIgnoreCase);
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
}
