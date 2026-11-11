// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Collections.Concurrent;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.Text.Encodings.Web;
using System.Text.Json.Nodes;
using Cratis.Arc.Identity;
using Cratis.AuthProxy.ForwardedIdentity;
using Cratis.AuthProxy.OnBehalfSessions;
using Cratis.AuthProxy.Telemetry;
using Cratis.Json;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Options;
using C = Cratis.AuthProxy.Configuration;

namespace Cratis.AuthProxy.Identity;

/// <summary>
/// Calls every service's <c language="text">/.cratis/me</c> endpoint to retrieve application-specific
/// identity details, merges the JSON results, converts them to an <see cref="IdentityProviderResult"/>
/// and stores it in the <c language="text">.cratis-identity</c> response cookie as a base64-encoded JSON string,
/// unless <see cref="C.Session.EmitIdentityDetailsCookie"/> is turned off.
/// </summary>
/// <param name="config">The auth proxy configuration.</param>
/// <param name="httpClientFactory">The HTTP client factory.</param>
/// <param name="principalEnrichers">Enrichers that augment the principal before it is sent to the identity endpoint.</param>
/// <param name="memoryCache">The memory cache used to deduplicate concurrent identity resolutions.</param>
/// <param name="authorizationCache">The tamper-proof record of a previously resolved authorization.</param>
/// <param name="logger">The logger.</param>
/// <param name="signer">The per-flow forwarded-identity signer.</param>
/// <remarks>
/// What each service's answer is worth is a per-service setting — see
/// <see cref="C.IdentityVerificationMode"/>. Under <see cref="C.IdentityVerificationMode.BestEffort"/> only
/// an HTTP <c language="text">403</c> denies, preserving earlier releases' behavior as an explicit opt-in. Under
/// <see cref="C.IdentityVerificationMode.Required"/> only an explicit positive admits, and every other
/// outcome denies and erases what an earlier positive left behind.
/// </remarks>
public class IdentityDetailsResolver(
    IOptionsMonitor<C.AuthProxy> config,
    IHttpClientFactory httpClientFactory,
    IEnumerable<IIdentityDetailsPrincipalEnricher> principalEnrichers,
    IMemoryCache memoryCache,
    IIdentityAuthorizationCache authorizationCache,
    ILogger<IdentityDetailsResolver> logger,
    IForwardedIdentitySigner signer) : IIdentityDetailsResolver
{
    /// <summary>
    /// The longest encoded value the readable identity cookie is allowed to carry. Browsers refuse a cookie
    /// larger than 4096 bytes (name and attributes included) and reverse proxies reject a response whose headers
    /// exceed their buffer (nginx answers 502 "upstream sent too big header"), so an identity that does not fit
    /// is not published through the cookie at all: a cookie is a cache of the identity, never the only copy of it.
    /// </summary>
    internal const int MaxIdentityCookieValueLength = 3072;

    const string CacheKeyPurpose = "IdentityDetails";

    /// <summary>
    /// The label a denial is logged under when the request never reached a service to be refused by one.
    /// </summary>
    const string ResolutionQueueLabel = "identity-resolution";

    static readonly JsonSerializerOptions _cookieSerializerOptions = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
        Converters = { new ConceptAsJsonConverterFactory() }
    };

    readonly ConcurrentDictionary<IdentityAccountTenantKey, SemaphoreSlim> _resolverLocks = new();
    readonly IdentityEndpointCaller _endpointCaller = new(httpClientFactory, logger, signer);

    /// <inheritdoc/>
    public async Task<IdentityProviderResult> Resolve(HttpContext context, ClientPrincipal principal, string tenantId)
    {
        using var activity = AuthProxyTelemetry.Start(WellKnownTelemetryNames.IdentityResolveSpan);
        var result = await ResolveIdentity(context, principal, tenantId, activity);

        // A refusal tags the span itself, so everything else is an authorization.
        if (activity?.GetTagItem(WellKnownTelemetryNames.IdentityOutcomeAttribute) is null)
        {
            AuthProxyTelemetry.IdentityResolved(activity, true);
        }

        return result;
    }

    /// <summary>
    /// Resolves the identity; the traced body of <see cref="Resolve"/>.
    /// </summary>
    /// <param name="context">The HTTP context.</param>
    /// <param name="principal">The caller.</param>
    /// <param name="tenantId">The tenant.</param>
    /// <param name="activity">The identity span started by <see cref="Resolve"/>, tagged when the caller is refused.</param>
    /// <returns>The identity provider result.</returns>
    internal async Task<IdentityProviderResult> ResolveIdentity(HttpContext context, ClientPrincipal principal, string tenantId, Activity? activity = null)
    {
        var state = BeginResolution(context, principal, tenantId, activity);

        if (SealedRecordAdmits(state))
        {
            AuthProxyTelemetry.IdentityCacheLookup(true);
            return BuildAuthorizedResult(principal, details: null);
        }

        if (TryServeCachedIdentity(state, out var cached))
        {
            return cached;
        }

        SemaphoreSlim? ownedSemaphore = null;
        var semaphore = state.CacheKey is not null
            ? _resolverLocks.GetOrAdd(state.CacheKey, _ => new SemaphoreSlim(1, 1))
            : ownedSemaphore = new SemaphoreSlim(1, 1);

        // The wait for a turn has to be bounded by the same two things the call itself is bounded by: the
        // caller's own request lifetime, and the budget the deployment stated for an answer. An unbounded
        // wait in front of a bounded call is still an unbounded call — every request for one account lines
        // up on this semaphore behind a verifier that accepts connections and stops answering, each turn
        // costs up to the verification timeout, and a client that gave up long ago keeps its place in the
        // queue. One page load's worth of assets is minutes of proxy work on that arithmetic.
        var (tookItsTurn, missedTurn) = await WaitForTurn(semaphore, state.Config, context);

        if (!tookItsTurn)
        {
            ownedSemaphore?.Dispose();
            return ResolveMissedTurn(state, missedTurn);
        }

        try
        {
            return await ResolveWithTurn(state);
        }
        finally
        {
            semaphore.Release();
            ownedSemaphore?.Dispose();
        }
    }

    static bool MayRemember(ResolutionState state, IReadOnlyCollection<string> verifiedRequiredServices) =>
        state.OnBehalf is null
        && state.CacheKey is not null
        && HasCacheableServiceSet(state.Session, verifiedRequiredServices, state.RequiredServices);

    /// <summary>
    /// Determines whether an outcome lets the request continue under a service's configured mode.
    /// </summary>
    /// <param name="outcome">What the service established.</param>
    /// <param name="mode">What the service's answer is worth.</param>
    /// <returns><see langword="true"/> when the request may continue; otherwise <see langword="false"/>.</returns>
    /// <remarks>
    /// <see cref="C.IdentityVerificationMode.BestEffort"/> denies on the one trigger the released proxy
    /// denied on — an HTTP <c language="text">403</c> — and on nothing else. The released call never read a verdict out of
    /// the body at all: it returned <c language="text">details</c> and forwarded the caller whatever the body said about
    /// <c language="text">isAuthorized</c>. Promoting a body-level negative to a denial in BestEffort would silently
    /// change the earlier releases' behavior for services that explicitly opt into this compatibility mode.
    /// <see cref="C.IdentityVerificationMode.Required"/> is where a body-level verdict becomes a decision.
    /// </remarks>
    static bool Admits(IdentityVerificationOutcome outcome, C.IdentityVerificationMode mode) =>
        outcome.Reason != IdentityVerificationReason.ForwardedIdentityNotSigned &&
        (mode == C.IdentityVerificationMode.Required
            ? outcome.Status == IdentityVerificationStatus.Positive
            : outcome.Reason != IdentityVerificationReason.Forbidden);

    /// <summary>
    /// Computes how long a request may wait for its turn at the identity endpoints.
    /// </summary>
    /// <param name="config">The configuration the request is being resolved against.</param>
    /// <returns>The bound, or <see cref="Timeout.InfiniteTimeSpan"/> when any participating service states none.</returns>
    /// <remarks>
    /// One resolution asks every participating service in turn, so the longest a turn can legitimately take
    /// is the sum of what each service is allowed. Waiting longer than that is waiting for a queue rather
    /// than for an answer. A single participating service that states no bound makes the whole sum
    /// unbounded — cutting the wait short there would refuse a request whose predecessor is still doing
    /// exactly what it was configured to be allowed to do. The caller's own request lifetime bounds the wait
    /// either way.
    /// </remarks>
    static TimeSpan QueueBudget(C.AuthProxy config)
    {
        var budgets = config.Services.Values
            .Where(service => service.ParticipatesInIdentityResolution)
            .Select(service => service.EffectiveIdentityVerificationTimeout)
            .ToList();

        return budgets.Count > 0 && budgets.TrueForAll(budget => budget > TimeSpan.Zero)
            ? budgets.Aggregate(TimeSpan.Zero, (total, budget) => total + budget)
            : Timeout.InfiniteTimeSpan;
    }

    /// <summary>
    /// Expires a readable identity cookie the request still carries when the deployment no longer writes it.
    /// </summary>
    /// <param name="context">The current <see cref="HttpContext"/>.</param>
    /// <param name="session">The session settings of the configuration snapshot in use.</param>
    static void RetireLegacyIdentityCookie(HttpContext context, C.Session session)
    {
        if (!session.EmitIdentityDetailsCookie && context.Request.Cookies.ContainsKey(Cookies.Identity))
        {
            ExpireIdentityCookie(context);
        }
    }

    /// <summary>
    /// Expires the readable identity cookie so a refused caller stops carrying an authorized-looking one.
    /// </summary>
    /// <param name="context">The current <see cref="HttpContext"/>.</param>
    static void ExpireIdentityCookie(HttpContext context) =>
        context.Response.Cookies.Delete(Cookies.Identity, new CookieOptions
        {
            HttpOnly = false,
            SameSite = SameSiteMode.Lax,
            Secure = context.Request.IsHttps,
        });

    static bool ReadableIdentityNamesAnotherCaller(HttpContext context, ClientPrincipal principal)
    {
        if (!context.Request.Cookies.TryGetValue(Cookies.Identity, out var value) || string.IsNullOrEmpty(value))
        {
            return false;
        }

        if (value.Length > MaxIdentityCookieValueLength)
        {
            return true;
        }

        var bytes = new byte[value.Length];
        if (!Convert.TryFromBase64String(value, bytes, out var bytesWritten))
        {
            return true;
        }

        try
        {
            using var document = JsonDocument.Parse(bytes.AsMemory(0, bytesWritten));
            return !ReadableIdentityMatchesCaller(document.RootElement, principal);
        }
        catch (JsonException)
        {
            // Unreadable identity state must be resolved again, not trusted to display the caller.
            return true;
        }
        catch (InvalidOperationException)
        {
            // Parsing can succeed even when GetString cannot decode malformed Unicode.
            return true;
        }
    }

    static bool ReadableIdentityMatchesCaller(JsonElement identity, ClientPrincipal principal)
    {
        if (identity.ValueKind != JsonValueKind.Object || !identity.TryGetProperty("id", out var id))
        {
            return false;
        }

        if (id.ValueKind != JsonValueKind.String || !string.Equals(id.GetString(), principal.UserId, StringComparison.Ordinal))
        {
            return false;
        }

        var name = identity.TryGetProperty("name", out var property) ? property : default;
        return ReadableNameMatchesCaller(name, principal.UserDetails);
    }

    static bool ReadableNameMatchesCaller(JsonElement name, string expectedName) => name.ValueKind switch
    {
        JsonValueKind.Undefined or JsonValueKind.Null => expectedName.Length == 0,
        JsonValueKind.String => string.Equals(name.GetString(), expectedName, StringComparison.Ordinal),
        _ => false
    };

    static async Task<(bool TookItsTurn, IdentityVerificationReason MissedTurn)> WaitForTurn(SemaphoreSlim semaphore, C.AuthProxy current, HttpContext context)
    {
        try
        {
            var tookItsTurn = await semaphore.WaitAsync(QueueBudget(current), context.RequestAborted);
            return (tookItsTurn, IdentityVerificationReason.TimedOut);
        }
        catch (OperationCanceledException)
        {
            return (false, IdentityVerificationReason.Canceled);
        }
    }

    static IEnumerable<KeyValuePair<string, C.Service>> ParticipatingServices(C.AuthProxy current, OnBehalfContext? onBehalf) =>
        current.Services.Where(_ => _.Value.ParticipatesInIdentityResolution && (onBehalf is null || current.OnBehalf?.Permits(_.Key) == true));

    static void MergeDetails(JsonObject mergedDetails, JsonObject details)
    {
        foreach (var property in details)
        {
            mergedDetails[property.Key] = property.Value?.DeepClone();
        }
    }

    static bool HasCacheableServiceSet(C.Session session, IReadOnlyCollection<string> verifiedRequiredServices, IReadOnlyCollection<string> requiredServices) =>
        session.IdentityResultCacheDuration > TimeSpan.Zero
        && verifiedRequiredServices.Order(StringComparer.Ordinal).SequenceEqual(requiredServices, StringComparer.Ordinal);

    /// <summary>
    /// Resolves the identity while holding the account's turn at the identity endpoints.
    /// </summary>
    /// <param name="state">What is known about the request being resolved.</param>
    /// <returns>The identity provider result.</returns>
    async Task<IdentityProviderResult> ResolveWithTurn(ResolutionState state)
    {
        // Double-check inside the lock — another request may have populated the cache while we waited.
        if (TryServeCachedIdentity(state, out var cached))
        {
            return cached;
        }

        AuthProxyTelemetry.IdentityCacheLookup(false);
        var enrichedPrincipal = principalEnrichers.Aggregate(state.Principal, (p, enricher) => enricher.Enrich(state.Context, p));
        var mergedDetails = new JsonObject();
        List<string> verifiedRequiredServices = [];

        var denied = await AskServices(state, enrichedPrincipal, mergedDetails, verifiedRequiredServices);
        if (denied is not null)
        {
            return denied;
        }

        var identityResult = BuildAuthorizedResult(state.Principal, mergedDetails.Count > 0 ? mergedDetails : null);
        WriteIdentityState(state, identityResult, verifiedRequiredServices);
        logger.IdentityDetailsCookieWritten(state.LogIdentifier);
        if (MayRemember(state, verifiedRequiredServices))
        {
            memoryCache.Set(state.CacheKey!, identityResult, state.Session.IdentityResultCacheDuration);
        }

        return identityResult;
    }

    /// <summary>
    /// Asks every participating service for identity details, merging what they answer.
    /// </summary>
    /// <param name="state">What is known about the request being resolved.</param>
    /// <param name="enrichedPrincipal">The principal as the enrichers left it.</param>
    /// <param name="mergedDetails">Receives the details every admitting service returned.</param>
    /// <param name="verifiedRequiredServices">Receives the names of the Required services that admitted.</param>
    /// <returns>The unauthorized result when a service refused; otherwise <see langword="null"/>.</returns>
    async Task<IdentityProviderResult?> AskServices(ResolutionState state, ClientPrincipal enrichedPrincipal, JsonObject mergedDetails, List<string> verifiedRequiredServices)
    {
        foreach (var (name, service) in ParticipatingServices(state.Config, state.OnBehalf))
        {
            logger.CallingIdentityEndpointWithPrincipal(name, state.LogIdentifier);
            var mode = service.IdentityVerification;
            var required = mode == C.IdentityVerificationMode.Required;

            var outcome = await _endpointCaller.Call(
                new IdentityEndpointCall(
                    name,
                    service.Backend!.BaseUrl,
                    enrichedPrincipal,
                    state.TenantId,
                    state.LogIdentifier,
                    service.EffectiveIdentityVerificationTimeout,
                    DenialWillBeLogged: required,
                    OnBehalf: state.OnBehalf),
                state.Context.RequestAborted);

            if (!Admits(outcome, mode))
            {
                return DenyService(state, name, outcome.Reason, required);
            }

            if (required)
            {
                verifiedRequiredServices.Add(name);
            }

            MergeDetails(mergedDetails, outcome.Details);
        }

        return null;
    }

    ResolutionState BeginResolution(HttpContext context, ClientPrincipal principal, string tenantId, Activity? activity)
    {
        // When a pending invite is in-flight the cookie and memory caches must be bypassed so that
        // the enriched principal (which carries the invite claims jti/invite_type) is always sent to
        // the identity endpoint. A stale .cratis-identity cookie from a previous session would
        // otherwise shadow the invite claims and cause the Lobby to return the wrong flow type.
        var current = config.CurrentValue;
        var session = current.Session;
        var hasPendingInvite = context.HasPendingInvitation();

        // Every exit path, the sealed fast path included, must retire a legacy copy of the readable cookie.
        RetireLegacyIdentityCookie(context, session);

        var hasReusableBinding = IdentityAccountBinding.TryCreate(principal, current.Authentication.TotalProviderCount, out var account);
        var requiredServices = IdentityVerificationServices.Required(current);

        // An on-behalf session neither reuses nor leaves behind a remembered result: one remembered from the user's own
        // sign-in would skip asking the application with the actor named, and one remembered from the session would
        // later stand in for the user's own sign-in. The services asked during a session are also only those the
        // session may reach, so a result from it never stands for the full set.
        var onBehalf = context.TryGetOnBehalf(out var active) ? active : null;

        // A remembered result proves only the Required service set it was produced under. A mode change
        // must ask the newly Required services, never seal an earlier BestEffort admission as verification.
        var cachePurpose = CacheKeyPurpose + JsonSerializer.Serialize(requiredServices);

        return new ResolutionState
        {
            Context = context,
            Principal = principal,
            TenantId = tenantId,
            Config = current,
            CacheKey = hasReusableBinding ? IdentityAccountTenantKey.Create(cachePurpose, account, tenantId) : null,
            LogIdentifier = hasReusableBinding ? account.GetLogIdentifier() : "invalid-canonical-account",
            HasPendingInvite = hasPendingInvite,
            MayReuseResult = !hasPendingInvite && onBehalf is null && session.IdentityResultCacheDuration > TimeSpan.Zero,
            OnBehalf = onBehalf,
            RequiredServices = requiredServices,
            Activity = activity
        };
    }

    bool SealedRecordAdmits(ResolutionState state)
    {
        var session = state.Session;

        // Every short-circuit is a remembered answer standing in for asking again, so where the answer
        // is an authorization decision a deployment must be able to switch the memory off and have it
        // actually be off. A zero re-validation interval is documented as "no bound", and honoring that
        // literally means nothing may be sealed — so nothing may be believed either.
        var mayReuseRecord = !state.HasPendingInvite
            && (!state.VerificationRequired || session.IdentityRevalidationInterval > TimeSpan.Zero);

        // Skipping the identity endpoints means skipping the authorization answer they carry, so what
        // permits the skip has to be something the caller could not have written. The readable
        // .cratis-identity cookie is not that — it is non-HTTP-only by design and its value was never
        // examined here, so sending any value for it used to be enough to be treated as authorized, for as
        // long as the caller chose to keep sending it. The sealed record is checked instead, and it is
        // checked against this principal and this tenant.
        // The readable cookie can only cause more checking, never less, so it stays non-evidence.
        return mayReuseRecord
            && !ReadableIdentityNamesAnotherCaller(state.Context, state.Principal)
            && authorizationCache.IsAuthorized(state.Context, state.Principal, state.TenantId);
    }

    IdentityProviderResult ResolveMissedTurn(ResolutionState state, IdentityVerificationReason missedTurn)
    {
        // A caller that went away is an ordinary event and says nothing about the deployment. Running out
        // of budget while waiting is the operator's signal that the identity endpoints are the queue.
        if (missedTurn == IdentityVerificationReason.TimedOut && !state.VerificationRequired)
        {
            logger.IdentityResolutionQueueExhausted(state.LogIdentifier);
        }

        // Never reaching the call establishes precisely what a call that never answers establishes, so
        // the two ways of missing a turn are worth what their call-level equivalents are worth: nothing
        // under Required, and no extra details otherwise. Nothing is sealed on this path either way.
        return state.VerificationRequired
            ? DenyUnreached(state, missedTurn)
            : BuildAuthorizedResult(state.Principal, details: null);
    }

    bool TryServeCachedIdentity(ResolutionState state, [NotNullWhen(true)] out IdentityProviderResult? cached)
    {
        if (!TryGetCachedIdentity(state.MayReuseResult, state.CacheKey, out cached))
        {
            return false;
        }

        WriteIdentityState(state, cached, state.RequiredServices);
        logger.IdentityDetailsCacheHit(state.LogIdentifier);
        AuthProxyTelemetry.IdentityCacheLookup(true);
        return true;
    }

    bool TryGetCachedIdentity(bool mayReuseResult, IdentityAccountTenantKey? cacheKey, [NotNullWhen(true)] out IdentityProviderResult? cached)
    {
        cached = null;
        if (!mayReuseResult || cacheKey is null)
        {
            return false;
        }

        return memoryCache.TryGetValue(cacheKey, out cached) && cached is not null;
    }

    IdentityProviderResult BuildAuthorizedResult(ClientPrincipal principal, object? details) =>
        new(
            principal.UserId,
            principal.UserDetails,
            IsAuthenticated: true,
            IsAuthorized: true,
            principal.UserRoles,
            details!);

    /// <summary>
    /// Refuses the request because a service refused, or could not be verified, and erases every trace of an earlier positive.
    /// </summary>
    /// <param name="state">What is known about the request being resolved.</param>
    /// <param name="serviceName">The service that refused, or that could not be verified.</param>
    /// <param name="reason">The bounded code explaining the refusal.</param>
    /// <param name="required">Whether the refusing service requires verification.</param>
    /// <returns>The unauthorized result.</returns>
    IdentityProviderResult DenyService(ResolutionState state, string serviceName, IdentityVerificationReason reason, bool required)
    {
        if (reason == IdentityVerificationReason.Canceled)
        {
            logger.IdentityVerificationCanceled(serviceName);
        }
        else if (required)
        {
            logger.RequiredIdentityVerificationDenied(serviceName, reason.ToString());
        }
        else
        {
            logger.IdentityVerificationDenied(serviceName, reason);
        }

        return Refuse(state, reason);
    }

    /// <summary>
    /// Refuses the request because resolution never reached an endpoint, and erases every trace of an earlier positive.
    /// </summary>
    /// <param name="state">What is known about the request being resolved.</param>
    /// <param name="reason">The bounded code explaining the refusal.</param>
    /// <returns>The unauthorized result.</returns>
    IdentityProviderResult DenyUnreached(ResolutionState state, IdentityVerificationReason reason)
    {
        if (reason == IdentityVerificationReason.Canceled)
        {
            logger.IdentityVerificationCanceled(ResolutionQueueLabel);
        }
        else
        {
            logger.RequiredIdentityResolutionDenied(state.RequiredServices, reason.ToString());
        }

        return Refuse(state, reason);
    }

    /// <summary>
    /// Records the refusal and erases every trace of an earlier positive.
    /// </summary>
    /// <param name="state">What is known about the request being resolved.</param>
    /// <param name="reason">The bounded code explaining the refusal.</param>
    /// <returns>The unauthorized result.</returns>
    /// <remarks>
    /// Refusing without erasing would be nearly useless: an earlier success leaves a sealed record, a
    /// readable cookie and an in-memory result behind, and any one of them lets the very next request skip
    /// the question that was just answered no. All three go together, and they go on every refusal — the
    /// released code cleared none of them, and <c language="text">Clear</c> had no caller at all.
    /// </remarks>
    IdentityProviderResult Refuse(ResolutionState state, IdentityVerificationReason reason)
    {
        AuthProxyTelemetry.IdentityDenied(reason);
        AuthProxyTelemetry.IdentityResolved(state.Activity, false);
        authorizationCache.Clear(state.Context);
        ExpireIdentityCookie(state.Context);
        if (state.CacheKey is not null)
        {
            memoryCache.Remove(state.CacheKey);
        }

        state.Context.Response.StatusCode = StatusCodes.Status403Forbidden;

        return IdentityProviderResult.Unauthorized;
    }

    void WriteIdentityState(ResolutionState state, IdentityProviderResult result, IReadOnlyCollection<string> verifiedRequiredServices)
    {
        var context = state.Context;

        // Two cookies, deliberately: the readable one the frontend renders from (optional, see
        // Session.EmitIdentityDetailsCookie), and the sealed record
        // that is allowed to skip this resolution next time. They are written together so the authorized
        // outcome and the proof of it can never drift apart.
        authorizationCache.Record(context, state.Principal, state.TenantId, verifiedRequiredServices);

        if (!state.Session.EmitIdentityDetailsCookie)
        {
            return;
        }

        var json = JsonSerializer.Serialize(result, _cookieSerializerOptions);
        var encoded = Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes(json));

        // The cookie is a pure cache of the resolved identity details. Bounding it to the configured
        // re-validation interval makes the browser drop it periodically, which forces the details — and
        // the authorization decision they represent — to be re-resolved against the services without
        // paying a backend round-trip on every request. A non-positive interval keeps it a session cookie.
        var revalidationInterval = config.CurrentValue.Session.IdentityRevalidationInterval;

        if (encoded.Length > MaxIdentityCookieValueLength)
        {
            // Dropping the cookie (and any stale smaller one) beats an unbounded Set-Cookie header: a response
            // that is too big for the browser or the ingress takes the whole request down with it. The
            // frontend then reads the identity from the endpoint instead of the cookie.
            logger.IdentityCookieTooLarge(encoded.Length, MaxIdentityCookieValueLength);
            ExpireIdentityCookie(context);
            return;
        }

        context.Response.Cookies.Append(Cookies.Identity, encoded, new CookieOptions
        {
            HttpOnly = false,   // Must be readable by the frontend JS.
            SameSite = SameSiteMode.Lax,
            Secure = context.Request.IsHttps,
            MaxAge = revalidationInterval > TimeSpan.Zero ? revalidationInterval : null,
        });
    }

    /// <summary>
    /// What is known about one request being resolved, shared by the phases of the resolution.
    /// </summary>
    sealed class ResolutionState
    {
        /// <summary>Gets the current <see cref="HttpContext"/>.</summary>
        public required HttpContext Context { get; init; }

        /// <summary>Gets the caller.</summary>
        public required ClientPrincipal Principal { get; init; }

        /// <summary>Gets the tenant.</summary>
        public required string TenantId { get; init; }

        /// <summary>Gets the configuration snapshot the request is resolved against.</summary>
        public required C.AuthProxy Config { get; init; }

        /// <summary>Gets the in-memory result key for this caller, when there is one.</summary>
        public required IdentityAccountTenantKey? CacheKey { get; init; }

        /// <summary>Gets the identifier the caller is logged under.</summary>
        public required string LogIdentifier { get; init; }

        /// <summary>Gets a value indicating whether an invitation is pending for the request.</summary>
        public required bool HasPendingInvite { get; init; }

        /// <summary>Gets a value indicating whether a remembered in-memory result may stand in for resolving.</summary>
        public required bool MayReuseResult { get; init; }

        /// <summary>Gets the on-behalf session the request runs under, when there is one.</summary>
        public required OnBehalfContext? OnBehalf { get; init; }

        /// <summary>Gets the services whose verification is Required.</summary>
        public required string[] RequiredServices { get; init; }

        /// <summary>Gets the identity span, tagged when the caller is refused.</summary>
        public required Activity? Activity { get; init; }

        /// <summary>Gets the session settings of the configuration snapshot in use.</summary>
        public C.Session Session => Config.Session;

        /// <summary>Gets a value indicating whether any service requires verification.</summary>
        public bool VerificationRequired => RequiredServices.Length > 0;
    }
}
