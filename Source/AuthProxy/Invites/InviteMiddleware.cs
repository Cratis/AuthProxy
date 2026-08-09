// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Diagnostics.CodeAnalysis;
using System.Net.Http.Headers;
using System.Security.Claims;
using Cratis.AuthProxy.Authentication;
using Cratis.AuthProxy.ErrorPages;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Options;
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
///     After a successful OIDC login – detects the pending invite cookie, calls the Studio
///     exchange endpoint, deletes the cookie, and signals any required lobby redirect via
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
public class InviteMiddleware(
    RequestDelegate next,
    IInviteTokenValidator tokenValidator,
    IOptionsMonitor<C.AuthProxy> config,
    IOptionsMonitor<C.Authentication> authConfig,
    ITenantResolver tenantResolver,
    IHttpClientFactory httpClientFactory,
    IErrorPageProvider errorPageProvider,
    ILogger<InviteMiddleware> logger,
    ICanonicalIdentityResolver? canonicalIdentityResolver)
{
    /// <summary>The route prefix that triggers invite handling.</summary>
    public const string InvitePathPrefix = WellKnownPaths.InvitePathPrefix;

    /// <summary>
    /// Key used to store the post-exchange lobby redirect URL in <see cref="HttpContext.Items"/>.
    /// Set by Phase 2 when exchange succeeds and the invite is not tenant-issued.
    /// Read by <see cref="InviteRedirectMiddleware"/> to perform the actual redirect.
    /// </summary>
    public const string LobbyRedirectUrlItemKey = "Cratis.InviteLobbyRedirectUrl";

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
        : this(next, tokenValidator, config, authConfig, tenantResolver, httpClientFactory, errorPageProvider, logger, null)
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
                logger.InviteExchangeTokenValidationFailed(context.Request.Path);
                context.Response.Cookies.Delete(Cookies.InviteToken);

                var invalidPageName = validationResult == InviteTokenValidationResult.Expired
                    ? WellKnownPageNames.InvitationExpired
                    : WellKnownPageNames.InvitationInvalid;

                await errorPageProvider.WriteErrorPageAsync(
                    context,
                    invalidPageName,
                    StatusCodes.Status401Unauthorized);
                return;
            }

            var exchangeResult = await ExchangeInvite(context, inviteToken);
            context.Response.Cookies.Delete(Cookies.InviteToken);

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
                logger.InviteTokenValidationFailed(context.Request.Path);

                var pageName = validationResult == InviteTokenValidationResult.Expired
                    ? WellKnownPageNames.InvitationExpired
                    : WellKnownPageNames.InvitationInvalid;

                await errorPageProvider.WriteErrorPageAsync(
                    context,
                    pageName,
                    StatusCodes.Status401Unauthorized);
                return;
            }

            // Store the invite token in a short-lived, HTTP-only cookie.
            context.Response.Cookies.Append(Cookies.InviteToken, token, new CookieOptions
            {
                HttpOnly = true,
                SameSite = SameSiteMode.Lax,
                Secure = context.Request.IsHttps,
                MaxAge = TimeSpan.FromMinutes(15),
            });

            var currentAuthConfig = authConfig.CurrentValue;
            var providers = GetAllProviders(currentAuthConfig).ToList();

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
    /// Aggregates all configured OIDC and OAuth providers into a single enumerable of <see cref="OidcProviderInfo"/>.
    /// </summary>
    /// <param name="config">The authentication configuration containing the provider lists.</param>
    /// <returns>An enumerable of <see cref="OidcProviderInfo"/> for every configured provider.</returns>
    static IEnumerable<OidcProviderInfo> GetAllProviders(C.Authentication config) =>
        config.OidcProviders.Select(OidcProviderScheme.ToProviderInfo)
            .Concat(config.OAuthProviders.Select(OidcProviderScheme.ToProviderInfo));

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
        var logSubject = canonicalResolution.Identity is null ? subject : string.Empty;

        // An invitation is otherwise a pure bearer link - anyone with the URL could sign in with their
        // own account and be provisioned as the invited user. Bind the invite to its intended recipient by
        // requiring provider-supplied authenticated-session email evidence to match the invited email.
        var binding = EvaluateInvitedEmailBinding(inviteToken, email, emailVerified);
        if (binding == InviteExchangeResult.EmailUnavailable)
        {
            logger.InviteEmailUnavailable(logSubject);
            return binding;
        }

        if (binding == InviteExchangeResult.EmailMismatch)
        {
            logger.InviteEmailMismatch(logSubject);
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
            logger.InviteSubjectAlreadyExists(logSubject);
            return InviteExchangeResult.DuplicateSubject;
        }

        if (!response.IsSuccessStatusCode)
        {
            logger.InviteExchangeEndpointFailed((int)response.StatusCode, logSubject);
            return InviteExchangeResult.Failed;
        }

        logger.InviteExchangedSuccessfully(logSubject);
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
