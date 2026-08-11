// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Diagnostics.CodeAnalysis;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using Cratis.AuthProxy.Authentication;
using Cratis.AuthProxy.ErrorPages;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.JsonWebTokens;
using C = Cratis.AuthProxy.Configuration;

namespace Cratis.AuthProxy.Invites;

/// <summary>
/// Middleware that implements the two-phase invite flow:
/// <list type="number">
///   <item>
///     Handles <c>/invite/{token}</c> – validates the token, stores it in a short-lived
///     HTTP-only cookie and redirects the user to the OIDC login.
///     If multiple identity providers are configured — or the caller already carries a session, whose
///     identity is not the one this invitation may bind — the invitation provider-selection page is served
///     so the user chooses which provider to complete the invitation with.
///     If the token is expired the <c>invitation-expired.html</c> error page is returned.
///     If the token is malformed or has an invalid signature the <c>invitation-invalid.html</c> page is returned.
///   </item>
///   <item>
///     After a successful OIDC login – detects the pending invite cookie, confirms the session was
///     established by this invitation's own challenge, calls the Lobby invitation authority's
///     completion endpoint, deletes the cookie, and signals any required lobby redirect via
///     <see cref="LobbyRedirectUrlItemKey"/> in <see cref="HttpContext.Items"/> before
///     continuing the pipeline. Identity resolution and the actual redirect are handled by
///     <see cref="Identity.IdentityMiddleware"/> and <see cref="InviteRedirectMiddleware"/>
///     respectively.
///   </item>
/// </list>
/// The exchange itself lives in <see cref="IInviteCompletion"/>, shared with
/// <see cref="InviteCallbackCompletion"/> — which completes an invitation on the provider callback itself
/// whenever the challenge's capability binding survives the round trip. Phase 2 here remains fully intact as
/// the fallback for every callback that binding does not come back on, and both phases additionally
/// recognize a session that already completed its invitation on the callback so a stale pending cookie or a
/// return visit to the invitation URL never re-runs the exchange or re-offers provider selection.
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
    /// <remarks>
    /// This mechanism belongs to the middleware pipeline alone. When an invitation completes on the provider
    /// callback instead, <see cref="InviteCallbackCompletion"/> owns the response directly and places the
    /// lobby target on the remote handler's return URI — no item key is involved there.
    /// </remarks>
    public const string LobbyRedirectUrlItemKey = "Cratis.InviteLobbyRedirectUrl";

    static readonly JsonSerializerOptions _providerSerializerOptions = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        Converters = { new JsonStringEnumConverter() }
    };

    readonly InviteCompletion _completion = new(
        tokenValidator,
        config,
        authConfig,
        tenantResolver,
        httpClientFactory,
        logger,
        canonicalIdentityResolver,
        attestationIssuer,
        entryStateProtector);

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
                await RejectPendingInvitation(context, validationResult);
                return;
            }

            // A session that already completed this exact invitation on its own provider callback is never
            // exchanged again - the cookie arriving here is a stale copy the browser had not yet dropped.
            // Clear it and take the caller where the completed invitation leads.
            if (WasInvitationCompletedByThisSession(context, inviteToken))
            {
                await ContinueCompletedInvitation(context, inviteToken);
                return;
            }

            // "Authenticated" and "authenticated for this invitation" are different facts, and only the
            // second one may complete it. An invitation binds an organization to an identity permanently,
            // and the pre-existing session is the one that arrives first: a person already signed in with
            // one provider who opens an invitation and picks another was otherwise bound to the provider
            // they did not choose - silently, and with no way back. The session that answers the
            // invitation's own challenge carries AuthProxy's capability binding; nothing else does, so
            // nothing else is exchanged.
            if (WasAuthenticatedForInvitation(context, inviteToken, tokenValidator))
            {
                await CompleteInvitation(context, inviteToken);
                return;
            }

            // Not a failure - the invitation is still pending and still valid, it just has no identity to
            // bind yet. Falling through leaves the capability cookie in place and takes the caller to the
            // invitation's own provider selection (Phase 1), or lets the pipeline reach the challenge
            // endpoint the caller is already on their way to.
            logger.InviteSessionWasNotEstablishedByTheInvitation();
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

            // A signed-in caller returning to an invitation URL their own session has already completed -
            // the provider callback completed it before redirecting here - is never re-staged and never
            // offered provider selection again; they continue to where the completed invitation leads.
            if (context.User.Identity?.IsAuthenticated == true
                && WasInvitationCompletedByThisSession(context, token))
            {
                await ContinueCompletedInvitation(context, token);
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

            // A caller that already carries a session is never challenged straight through, however few
            // providers are configured. The session it arrived with is not the identity this invitation may
            // bind — that one is established by the challenge — and going straight to a provider gives the
            // person no chance to see, let alone change, which account the organization ends up bound to.
            // The click costs a moment; the wrong binding is permanent. A page is also terminal, so a
            // deployment where the invitation binding fails to survive the provider round-trip stops here
            // rather than bouncing the browser between the invitation and the provider forever.
            var isAlreadyAuthenticated = context.User.Identity?.IsAuthenticated == true;
            if (providers.Count > 1 || (providers.Count == 1 && isAlreadyAuthenticated))
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
                else if (InvitationAuthenticationState.TryBindPendingInvitation(context, properties))
                {
                    // Nothing was staged, so bind the capability this challenge is being started for. It is
                    // what proves, on the way back, that the session completing the invitation is the one
                    // this invitation challenged for. The request's own cookie cannot say so — it is being
                    // written by this very response.
                    InvitationAuthenticationState.BindCapability(properties, token);
                }
                else
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
    /// Determines whether a claim value is an email address rather than a username.
    /// </summary>
    /// <param name="value">The claim value to check.</param>
    /// <returns><see langword="true"/> when the value carries a local part and a domain; otherwise <see langword="false"/>.</returns>
    internal static bool IsAnEmailAddress([NotNullWhen(true)] string? value)
    {
        var at = value?.IndexOf('@', StringComparison.Ordinal) ?? -1;
        return at > 0 && at < value!.Length - 1;
    }

    /// <summary>
    /// Determines whether the session authenticating this request was established by this invitation's own challenge.
    /// </summary>
    /// <param name="context">The current <see cref="HttpContext"/>.</param>
    /// <param name="inviteToken">The pending invitation capability.</param>
    /// <param name="tokenValidator">The validator used to read the invitation's issue instant.</param>
    /// <returns><see langword="true"/> when the session answers this invitation; otherwise <see langword="false"/>.</returns>
    /// <remarks>
    /// The evidence read is the authentication result that produced <see cref="HttpContext.User"/> — the
    /// ticket the provider handshake signed in — rather than a second authentication call naming a scheme,
    /// so the question asked is exactly "what established the identity this request is running as". A
    /// deployment authenticating by any other means carries no invitation binding and is therefore refused,
    /// which is the intended direction: the invite flow is a browser flow AuthProxy challenges for itself.
    /// </remarks>
    static bool WasAuthenticatedForInvitation(HttpContext context, string inviteToken, IInviteTokenValidator tokenValidator)
    {
        var properties = context.Features.Get<IAuthenticateResultFeature>()?.AuthenticateResult?.Properties;
        if (InvitationAuthenticationState.WasEstablishedFor(properties, inviteToken))
        {
            return true;
        }

        // The capability binding is the strongest evidence, but it rides in custom challenge properties
        // whose survival depends on every handler in the round trip. The session's issue instant does not:
        // the framework stamps and persists it itself. A session issued AFTER the invitation came into
        // existence was signed in by a person already holding the invitation — their deliberate choice for
        // it — while the session the original defect wrongly consumed was, by definition, one that already
        // existed before the invitation did. Gating on the order of those two instants can neither rebind
        // an old session nor strand a fresh sign-in in an endless provider-selection loop.
        var issuedAt = properties?.IssuedUtc;
        if (issuedAt is null
            || !tokenValidator.TryGetClaim(inviteToken, JwtRegisteredClaimNames.Iat, out var invitationIssuedAt)
            || !long.TryParse(invitationIssuedAt, out var invitationIssuedAtSeconds))
        {
            return false;
        }

        return issuedAt.Value >= DateTimeOffset.FromUnixTimeSeconds(invitationIssuedAtSeconds);
    }

    /// <summary>
    /// Determines whether the session authenticating this request has already completed the exchange for
    /// this exact invitation — on its own provider callback.
    /// </summary>
    /// <param name="context">The current <see cref="HttpContext"/>.</param>
    /// <param name="inviteToken">The invitation capability being presented.</param>
    /// <returns><see langword="true"/> when this session already completed that capability; otherwise <see langword="false"/>.</returns>
    static bool WasInvitationCompletedByThisSession(HttpContext context, string inviteToken)
    {
        var properties = context.Features.Get<IAuthenticateResultFeature>()?.AuthenticateResult?.Properties;
        return InvitationAuthenticationState.WasCompletedFor(properties, inviteToken);
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

    static bool FixedTimeEquals(string expected, string actual) =>
        CryptographicOperations.FixedTimeEquals(Encoding.UTF8.GetBytes(expected), Encoding.UTF8.GetBytes(actual));

    bool IsAttestedProtocolEnabled() => config.CurrentValue.Invite?.Attestation is not null;

    /// <summary>
    /// Answers a pending invitation whose capability no longer validates, and clears it from the browser.
    /// </summary>
    /// <param name="context">The current <see cref="HttpContext"/>.</param>
    /// <param name="validationResult">The reason re-validation refused the capability.</param>
    /// <returns>A <see cref="Task"/> that represents the asynchronous operation.</returns>
    async Task RejectPendingInvitation(HttpContext context, InviteTokenValidationResult validationResult)
    {
        PendingInvitationCookies.Delete(context);

        var invalidPageName = validationResult == InviteTokenValidationResult.Expired
            ? WellKnownPageNames.InvitationExpired
            : WellKnownPageNames.InvitationInvalid;

        await errorPageProvider.WriteErrorPageAsync(
            context,
            invalidPageName,
            StatusCodes.Status401Unauthorized);
    }

    /// <summary>
    /// Continues a request whose session has already completed the invitation it presents: the stale pending
    /// state is cleared and the caller is taken where the completed invitation leads — the lobby for a
    /// non-tenant-issued invitation, the pipeline's own course otherwise.
    /// </summary>
    /// <param name="context">The current <see cref="HttpContext"/>.</param>
    /// <param name="inviteToken">The already-completed invitation capability.</param>
    /// <returns>A <see cref="Task"/> that represents the asynchronous operation.</returns>
    async Task ContinueCompletedInvitation(HttpContext context, string inviteToken)
    {
        PendingInvitationCookies.Delete(context);

        if (_completion.TryResolveLobbyRedirect(context, inviteToken, out var lobbyRedirectUrl))
        {
            context.Items[LobbyRedirectUrlItemKey] = lobbyRedirectUrl;
        }

        await next(context);
    }

    /// <summary>
    /// Completes a pending invitation with the identity that answered its challenge, and answers whatever
    /// the completion produced.
    /// </summary>
    /// <param name="context">The current <see cref="HttpContext"/>.</param>
    /// <param name="inviteToken">The re-validated invitation capability.</param>
    /// <returns>A <see cref="Task"/> that represents the asynchronous operation.</returns>
    async Task CompleteInvitation(HttpContext context, string inviteToken)
    {
        var exchangeResult = await _completion.ExchangeForRequest(context, inviteToken);
        PendingInvitationCookies.Delete(context);

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

        if (exchangeResult == InviteExchangeResult.Success
            && _completion.TryResolveLobbyRedirect(context, inviteToken, out var lobbyRedirectUrl))
        {
            context.Items[LobbyRedirectUrlItemKey] = lobbyRedirectUrl;
        }

        await next(context);
    }

    async Task<(bool Succeeded, InvitationEntryState? State)> StageInvitation(HttpContext context, string inviteToken)
    {
        var invite = config.CurrentValue.Invite;
        if (invite is null
            || attestationIssuer is null
            || entryStateProtector is null
            || inviteToken.Length > InviteCompletion.MaximumAttestedInvitationTokenLength
            || string.IsNullOrWhiteSpace(invite.StageUrl)
            || string.IsNullOrWhiteSpace(invite.TenantClaim)
            || !InviteCompletion.TryGetSingleTokenClaim(inviteToken, JwtRegisteredClaimNames.Jti, out var invitationId)
            || !InviteCompletion.TryGetSingleTokenClaim(inviteToken, invite.TenantClaim, out var tenantId)
            || !_completion.ResolvedTenantMatchesWhenPresent(context, tenantId))
        {
            return (false, null);
        }

        var entryState = new InvitationEntryState(
            tenantId,
            invitationId,
            InvitationAttestationIssuer.CreateOpaqueValue(),
            InvitationAttestationIssuer.CreateOpaqueValue(),
            InvitationAuthenticationState.ComputeCapabilityHash(inviteToken),
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
}
