// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Collections.Concurrent;
using System.Text.Encodings.Web;
using System.Text.Json.Nodes;
using Cratis.Arc.Identity;
using Cratis.Json;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Options;
using C = Cratis.AuthProxy.Configuration;

namespace Cratis.AuthProxy.Identity;

/// <summary>
/// Calls every service's <c>/.cratis/me</c> endpoint to retrieve application-specific
/// identity details, merges the JSON results, converts them to an <see cref="IdentityProviderResult"/>
/// and stores it in the <c>.cratis-identity</c> response cookie as a base64-encoded JSON string.
/// </summary>
/// <param name="config">The auth proxy configuration.</param>
/// <param name="httpClientFactory">The HTTP client factory.</param>
/// <param name="principalEnrichers">Enrichers that augment the principal before it is sent to the identity endpoint.</param>
/// <param name="memoryCache">The memory cache used to deduplicate concurrent identity resolutions.</param>
/// <param name="authorizationCache">The tamper-proof record of a previously resolved authorization.</param>
/// <param name="logger">The logger.</param>
/// <remarks>
/// What each service's answer is worth is a per-service setting — see
/// <see cref="C.IdentityVerificationMode"/>. Under <see cref="C.IdentityVerificationMode.BestEffort"/> only
/// an HTTP <c>403</c> denies, which is exactly what the released proxy denied on and nothing more. Under
/// <see cref="C.IdentityVerificationMode.Required"/> only an explicit positive admits, and every other
/// outcome denies and erases what an earlier positive left behind.
/// </remarks>
public class IdentityDetailsResolver(
    IOptionsMonitor<C.AuthProxy> config,
    IHttpClientFactory httpClientFactory,
    IEnumerable<IIdentityDetailsPrincipalEnricher> principalEnrichers,
    IMemoryCache memoryCache,
    IIdentityAuthorizationCache authorizationCache,
    ILogger<IdentityDetailsResolver> logger) : IIdentityDetailsResolver
{
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
    readonly IdentityEndpointCaller _endpointCaller = new(httpClientFactory, logger);

    /// <inheritdoc/>
    public async Task<IdentityProviderResult> Resolve(HttpContext context, ClientPrincipal principal, string tenantId)
    {
        // When a pending invite is in-flight the cookie and memory caches must be bypassed so that
        // the enriched principal (which carries the invite claims jti/invite_type) is always sent to
        // the identity endpoint. A stale .cratis-identity cookie from a previous session would
        // otherwise shadow the invite claims and cause the Lobby to return the wrong flow type.
        var current = config.CurrentValue;
        var session = current.Session;
        var hasPendingInvite = context.HasPendingInvitation();
        var hasReusableBinding = IdentityAccountBinding.TryCreate(principal, out var account);
        var logIdentifier = hasReusableBinding ? account.GetLogIdentifier() : "invalid-canonical-account";

        // Every short-circuit below is a remembered answer standing in for asking again, so where the answer
        // is an authorization decision a deployment must be able to switch the memory off and have it
        // actually be off. A zero re-validation interval is documented as "no bound", and honoring that
        // literally means nothing may be sealed — so nothing may be believed either.
        var verificationRequired = current.RequiresIdentityVerification;
        var mayReuseRecord = !hasPendingInvite
            && (!verificationRequired || session.IdentityRevalidationInterval > TimeSpan.Zero);
        var mayReuseResult = !hasPendingInvite && session.IdentityResultCacheDuration > TimeSpan.Zero;

        // Skipping the identity endpoints means skipping the authorization answer they carry, so what
        // permits the skip has to be something the caller could not have written. The readable
        // .cratis-identity cookie is not that — it is non-HTTP-only by design and its value was never
        // examined here, so sending any value for it used to be enough to be treated as authorized, for as
        // long as the caller chose to keep sending it. The sealed record is checked instead, and it is
        // checked against this principal and this tenant.
        if (mayReuseRecord && authorizationCache.IsAuthorized(context, principal, tenantId))
        {
            return BuildAuthorizedResult(principal, details: null);
        }

        var cacheKey = hasReusableBinding ? IdentityAccountTenantKey.Create(CacheKeyPurpose, account, tenantId) : null;

        if (mayReuseResult && cacheKey is not null && memoryCache.TryGetValue(cacheKey, out IdentityProviderResult? cached) && cached is not null)
        {
            WriteIdentityState(context, cached, principal, tenantId);
            logger.IdentityDetailsCacheHit(logIdentifier);
            return cached;
        }

        SemaphoreSlim? ownedSemaphore = null;
        var semaphore = cacheKey is not null
            ? _resolverLocks.GetOrAdd(cacheKey, _ => new SemaphoreSlim(1, 1))
            : ownedSemaphore = new SemaphoreSlim(1, 1);

        // The wait for a turn has to be bounded by the same two things the call itself is bounded by: the
        // caller's own request lifetime, and the budget the deployment stated for an answer. An unbounded
        // wait in front of a bounded call is still an unbounded call — every request for one account lines
        // up on this semaphore behind a verifier that accepts connections and stops answering, each turn
        // costs up to the verification timeout, and a client that gave up long ago keeps its place in the
        // queue. One page load's worth of assets is minutes of proxy work on that arithmetic.
        bool tookItsTurn;
        IdentityVerificationReason missedTurn;
        try
        {
            tookItsTurn = await semaphore.WaitAsync(QueueBudget(current), context.RequestAborted);
            missedTurn = IdentityVerificationReason.TimedOut;
        }
        catch (OperationCanceledException)
        {
            tookItsTurn = false;
            missedTurn = IdentityVerificationReason.Canceled;
        }

        if (!tookItsTurn)
        {
            ownedSemaphore?.Dispose();

            // A caller that went away is an ordinary event and says nothing about the deployment. Running out
            // of budget while waiting is the operator's signal that the identity endpoints are the queue.
            if (missedTurn == IdentityVerificationReason.TimedOut)
            {
                logger.IdentityResolutionQueueExhausted(logIdentifier);
            }

            // Never reaching the call establishes precisely what a call that never answers establishes, so
            // the two ways of missing a turn are worth what their call-level equivalents are worth: nothing
            // under Required, and no extra details otherwise. Nothing is sealed on this path either way.
            return verificationRequired
                ? Deny(context, cacheKey, ResolutionQueueLabel, missedTurn)
                : BuildAuthorizedResult(principal, details: null);
        }

        try
        {
            // Double-check inside the lock — another request may have populated the cache while we waited.
            if (mayReuseResult && cacheKey is not null && memoryCache.TryGetValue(cacheKey, out cached) && cached is not null)
            {
                WriteIdentityState(context, cached, principal, tenantId);
                logger.IdentityDetailsCacheHit(logIdentifier);
                return cached;
            }

            var enrichedPrincipal = principalEnrichers.Aggregate(principal, (p, enricher) => enricher.Enrich(context, p));
            var mergedDetails = new JsonObject();

            foreach (var (name, service) in current.Services.Where(_ => _.Value.ParticipatesInIdentityResolution))
            {
                logger.CallingIdentityEndpointWithPrincipal(name, logIdentifier);

                var outcome = await _endpointCaller.Call(
                    name,
                    service.Backend!.BaseUrl,
                    enrichedPrincipal,
                    tenantId,
                    logIdentifier,
                    service.EffectiveIdentityVerificationTimeout,
                    context.RequestAborted);

                if (!Admits(outcome, service.IdentityVerification))
                {
                    return Deny(context, cacheKey, name, outcome.Reason);
                }

                foreach (var property in outcome.Details)
                {
                    mergedDetails[property.Key] = property.Value?.DeepClone();
                }
            }

            var identityResult = BuildAuthorizedResult(principal, mergedDetails.Count > 0 ? mergedDetails : null);
            WriteIdentityState(context, identityResult, principal, tenantId);
            logger.IdentityDetailsCookieWritten(logIdentifier);
            if (cacheKey is not null && session.IdentityResultCacheDuration > TimeSpan.Zero)
            {
                memoryCache.Set(cacheKey, identityResult, session.IdentityResultCacheDuration);
            }

            return identityResult;
        }
        finally
        {
            semaphore.Release();
            ownedSemaphore?.Dispose();
        }
    }

    /// <summary>
    /// Determines whether an outcome lets the request continue under a service's configured mode.
    /// </summary>
    /// <param name="outcome">What the service established.</param>
    /// <param name="mode">What the service's answer is worth.</param>
    /// <returns><see langword="true"/> when the request may continue; otherwise <see langword="false"/>.</returns>
    /// <remarks>
    /// <see cref="C.IdentityVerificationMode.BestEffort"/> denies on the one trigger the released proxy
    /// denied on — an HTTP <c>403</c> — and on nothing else. The released call never read a verdict out of
    /// the body at all: it returned <c>details</c> and forwarded the caller whatever the body said about
    /// <c>isAuthorized</c>. Promoting a body-level negative to a denial here would change what the
    /// <em>default</em> mode does to services that never opted in, and would do it silently, to the exact
    /// response shape the documented envelope tells them to write.
    /// <see cref="C.IdentityVerificationMode.Required"/> is where a body-level verdict becomes a decision.
    /// </remarks>
    static bool Admits(IdentityVerificationOutcome outcome, C.IdentityVerificationMode mode) =>
        mode == C.IdentityVerificationMode.Required
            ? outcome.Status == IdentityVerificationStatus.Positive
            : outcome.Reason != IdentityVerificationReason.Forbidden;

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

    IdentityProviderResult BuildAuthorizedResult(ClientPrincipal principal, object? details) =>
        new(
            principal.UserId,
            principal.UserDetails,
            IsAuthenticated: true,
            IsAuthorized: true,
            principal.UserRoles,
            details!);

    /// <summary>
    /// Refuses the request and erases every trace of an earlier positive.
    /// </summary>
    /// <param name="context">The current <see cref="HttpContext"/>.</param>
    /// <param name="cacheKey">The in-memory result key for this caller, when there is one.</param>
    /// <param name="serviceName">The service that refused, or that could not be verified.</param>
    /// <param name="reason">The bounded code explaining the refusal.</param>
    /// <returns>The unauthorized result.</returns>
    /// <remarks>
    /// Refusing without erasing would be nearly useless: an earlier success leaves a sealed record, a
    /// readable cookie and an in-memory result behind, and any one of them lets the very next request skip
    /// the question that was just answered no. All three go together, and they go on every refusal — the
    /// released code cleared none of them, and <c>Clear</c> had no caller at all.
    /// </remarks>
    IdentityProviderResult Deny(HttpContext context, IdentityAccountTenantKey? cacheKey, string serviceName, IdentityVerificationReason reason)
    {
        logger.IdentityVerificationDenied(serviceName, reason);

        authorizationCache.Clear(context);
        ExpireIdentityCookie(context);
        if (cacheKey is not null)
        {
            memoryCache.Remove(cacheKey);
        }

        context.Response.StatusCode = StatusCodes.Status403Forbidden;

        return IdentityProviderResult.Unauthorized;
    }

    void WriteIdentityState(HttpContext context, IdentityProviderResult result, ClientPrincipal principal, string tenantId)
    {
        // Two cookies, deliberately: the readable one the frontend renders from, and the sealed record
        // that is allowed to skip this resolution next time. They are written together so the authorized
        // outcome and the proof of it can never drift apart.
        authorizationCache.Record(context, principal, tenantId);

        var json = JsonSerializer.Serialize(result, _cookieSerializerOptions);
        var encoded = Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes(json));

        // The cookie is a pure cache of the resolved identity details. Bounding it to the configured
        // re-validation interval makes the browser drop it periodically, which forces the details — and
        // the authorization decision they represent — to be re-resolved against the services without
        // paying a backend round-trip on every request. A non-positive interval keeps it a session cookie.
        var revalidationInterval = config.CurrentValue.Session.IdentityRevalidationInterval;

        context.Response.Cookies.Append(Cookies.Identity, encoded, new CookieOptions
        {
            HttpOnly = false,   // Must be readable by the frontend JS.
            SameSite = SameSiteMode.Lax,
            Secure = context.Request.IsHttps,
            MaxAge = revalidationInterval > TimeSpan.Zero ? revalidationInterval : null,
        });
    }
}
