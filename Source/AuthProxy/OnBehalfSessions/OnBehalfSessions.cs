// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Collections.Concurrent;
using Cratis.AuthProxy.Attestations;
using Cratis.AuthProxy.Authorization;
using Cratis.AuthProxy.Identity;
using Microsoft.Extensions.Options;
using C = Cratis.AuthProxy.Configuration;

namespace Cratis.AuthProxy.OnBehalfSessions;

/// <summary>
/// Starts, re-checks and ends on-behalf sessions.
/// </summary>
/// <param name="config">The auth proxy configuration monitor.</param>
/// <param name="cookies">The on-behalf session cookie.</param>
/// <param name="grants">The application's grant check.</param>
/// <param name="notifier">The application's session notifications.</param>
/// <param name="attestations">The issuer of the assertion forwarded with every on-behalf request.</param>
/// <param name="ledger">The per-instance record of fresh grants and ended sessions.</param>
/// <param name="logger">The logger.</param>
/// <remarks>
/// Every way this can go wrong goes towards the actor not acting as anybody: a session is only issued after a live
/// grant and an acknowledged start, a session whose grant is gone or whose actor is no longer the one signed in
/// is ended, and a grant that cannot be re-checked refuses the request rather than forwarding it as either identity.
/// </remarks>
public sealed class OnBehalfSessions(
    IOptionsMonitor<C.AuthProxy> config,
    OnBehalfSessionCookie cookies,
    IOnBehalfGrants grants,
    IOnBehalfSessionNotifier notifier,
    IOnBehalfAttestations attestations,
    OnBehalfSessionLedger ledger,
    ILogger<OnBehalfSessions> logger) : IOnBehalfSessions
{
    /// <summary>
    /// The longest a tenant, subject or issue may be.
    /// </summary>
    public const int MaximumValueLength = 256;

    /// <summary>
    /// The grant re-checks in flight, one per session: every request of a page load finding the answer stale waits for
    /// the same call rather than each asking the application.
    /// </summary>
    readonly ConcurrentDictionary<string, Lazy<Task<OnBehalfGrant>>> _rechecks = new(StringComparer.Ordinal);

    /// <inheritdoc/>
    public async Task<OnBehalfStartResult> Start(HttpContext context, OnBehalfStartRequest request)
    {
        var settings = config.CurrentValue.OnBehalf;
        if (settings is null)
        {
            return new(OnBehalfStartStatus.NotEnabled);
        }

        var actor = context.User.Identity?.IsAuthenticated == true ? context.BuildActorClientPrincipal() : null;
        if (actor is null || string.IsNullOrEmpty(actor.UserId))
        {
            return new(OnBehalfStartStatus.Unauthenticated);
        }

        if (!IsValid(request.Tenant) || !IsValid(request.Subject) || !IsValid(request.Issue)
            || string.Equals(request.Subject, actor.UserId, StringComparison.Ordinal))
        {
            return new(OnBehalfStartStatus.Invalid);
        }

        var decision = AccessPolicy.Evaluate(context.User, settings.ActorAuthorization.RequiredClaims);
        if (!settings.ActorAuthorization.HasRequirements || !decision.IsGranted)
        {
            logger.ActorNotPermitted(decision.UnsatisfiedClaim);
            return new(OnBehalfStartStatus.Forbidden);
        }

        if (cookies.TryRead(context, out var existing) && !ledger.HasEnded(existing.SessionId, out _) && existing.ExpiresAt > ledger.Now)
        {
            if (existing.Actor.Is(actor))
            {
                return new(OnBehalfStartStatus.Conflict);
            }

            // A session somebody else left behind on this browser is not this actor's to keep or to be blocked by. It
            // ends, and the application hears so, before this actor's own session starts.
            await EndSession(context, existing, OnBehalfSessionEndReason.ActorChanged);
        }

        var now = ledger.Now;
        var session = new OnBehalfSession(
            AttestationSigner.CreateOpaqueValue(),
            OnBehalfActor.From(actor),
            request.Tenant!,
            request.Subject!,
            request.Issue!,
            now,
            now.Add(settings.MaximumLifetime));

        var grant = await grants.Check(session, actor, context.RequestAborted);
        if (grant.Status is OnBehalfGrantStatus.NotLive or OnBehalfGrantStatus.Expired)
        {
            return new(OnBehalfStartStatus.NotGranted);
        }

        if (!grant.IsLive)
        {
            return new(OnBehalfStartStatus.Unavailable);
        }

        // A session the application has not recorded as started is a session nobody can account for, so a start it did
        // not acknowledge is not issued at all.
        if (!await notifier.Started(session, grant, context.RequestAborted))
        {
            logger.SessionStartNotAcknowledged();
            return new(OnBehalfStartStatus.Unavailable);
        }

        ledger.Remember(session.SessionId, grant, FreshUntil(session, grant, settings));
        ExpireIdentityState(context);
        cookies.Write(context, session);
        logger.SessionStarted(session.SessionId);
        return new(OnBehalfStartStatus.Started, session, grant);
    }

    /// <inheritdoc/>
    public async Task<OnBehalfResolution> Resolve(HttpContext context)
    {
        var settings = config.CurrentValue.OnBehalf;
        if (!cookies.TryRead(context, out var session))
        {
            OnBehalfSessionCookie.Delete(context);
            return OnBehalfResolution.None;
        }

        if (settings is null)
        {
            OnBehalfSessionCookie.Delete(context);
            return OnBehalfResolution.None;
        }

        if (ledger.HasEnded(session.SessionId, out var endedReason))
        {
            OnBehalfSessionCookie.Delete(context);
            ExpireIdentityState(context);
            return new(OnBehalfResolutionStatus.Ended, Reason: endedReason);
        }

        // The cookie is worth nothing on its own: it only ever extends the actor's own session. A request with no
        // signed-in caller, or with somebody else signed in, ends it and proceeds as whoever that is.
        var actor = context.User.Identity?.IsAuthenticated == true ? context.BuildActorClientPrincipal() : null;
        if (!session.Actor.Is(actor))
        {
            await EndSession(context, session, actor is null ? OnBehalfSessionEndReason.ActorSessionEnded : OnBehalfSessionEndReason.ActorChanged);
            return OnBehalfResolution.None;
        }

        if (session.ExpiresAt <= ledger.Now)
        {
            return await Ended(context, session, OnBehalfSessionEndReason.LifetimeExceeded);
        }

        if (!ledger.TryGetGrant(session.SessionId, out var grant))
        {
            try
            {
                grant = await Recheck(session, actor!, settings).WaitAsync(context.RequestAborted);
            }
            catch (OperationCanceledException)
            {
                return OnBehalfResolution.Unavailable;
            }

            switch (grant.Status)
            {
                case OnBehalfGrantStatus.NotLive:
                    return await Ended(context, session, OnBehalfSessionEndReason.GrantNotLive);
                case OnBehalfGrantStatus.Expired:
                    return await Ended(context, session, OnBehalfSessionEndReason.GrantExpired);
                case OnBehalfGrantStatus.Indeterminate:
                    return OnBehalfResolution.Unavailable;
            }
        }

        // The assertion is issued per request, once its service, method and path are known; a session whose assertions
        // could not be signed is refused here rather than at forwarding.
        if (!attestations.CanSign)
        {
            logger.AssertionCouldNotBeSigned();
            return OnBehalfResolution.Unavailable;
        }

        return new(OnBehalfResolutionStatus.Active, new OnBehalfContext(session, grant.Principal!, actor!.ToBase64(), attestations));
    }

    /// <inheritdoc/>
    public async Task<OnBehalfEndStatus> End(HttpContext context, OnBehalfSessionEndReason reason)
    {
        if (!cookies.TryRead(context, out var session))
        {
            OnBehalfSessionCookie.Delete(context);
            return OnBehalfEndStatus.NoSession;
        }

        return await EndSession(context, session, reason);
    }

    /// <summary>
    /// Expires the identity details cookie and the sealed authorization record, so neither outlives the identity they
    /// were written for when a session starts or ends.
    /// </summary>
    /// <param name="context">The current <see cref="HttpContext"/>.</param>
    /// <remarks>
    /// Both are written for whoever the request acted as. Left in place, the readable one keeps showing the frontend
    /// the represented user after the session ended, or the actor after it started, until the next resolution.
    /// </remarks>
    static void ExpireIdentityState(HttpContext context)
    {
        context.Response.Cookies.Delete(Cookies.Identity, new CookieOptions
        {
            HttpOnly = false,
            SameSite = SameSiteMode.Lax,
            Secure = context.Request.IsHttps,
        });
        context.Response.Cookies.Delete(Cookies.IdentityAuthorization);
    }

    static bool IsValid(string? value) =>
        !string.IsNullOrWhiteSpace(value)
        && value.Length <= MaximumValueLength
        && string.Equals(value, value.Trim(), StringComparison.Ordinal)
        && !value.Any(char.IsControl);

    /// <summary>
    /// Works out how long a live answer is trusted: the earliest of the re-check interval, the grant's own validity
    /// and the session's expiry.
    /// </summary>
    /// <param name="session">The session.</param>
    /// <param name="grant">The live grant.</param>
    /// <param name="settings">The on-behalf configuration.</param>
    /// <returns>When the answer must be asked about again.</returns>
    DateTimeOffset FreshUntil(OnBehalfSession session, OnBehalfGrant grant, C.OnBehalf settings) =>
        new[] { ledger.Now.Add(settings.RecheckInterval), grant.ValidUntil, session.ExpiresAt }.Min();

    /// <summary>
    /// Re-checks a session's grant, sharing one call among every request that needs it at the same time.
    /// </summary>
    /// <param name="session">The session.</param>
    /// <param name="actor">The actor, already confirmed to be the session's.</param>
    /// <param name="settings">The on-behalf configuration.</param>
    /// <returns>The application's answer.</returns>
    /// <remarks>
    /// The shared call is not tied to the request that started it, so one request going away does not fail the others;
    /// it is still bounded by <see cref="C.OnBehalf.Timeout"/>. A live answer is remembered before the call is
    /// released, so a request arriving just after it finds the fresh grant instead of asking again.
    /// </remarks>
    Task<OnBehalfGrant> Recheck(OnBehalfSession session, ClientPrincipal actor, C.OnBehalf settings)
    {
        var recheck = _rechecks.GetOrAdd(
            session.SessionId,
            static (_, state) => new(() => state.Sessions.CheckAndRemember(state.Session, state.Actor, state.Settings)),
            (Sessions: this, Session: session, Actor: actor, Settings: settings));
        return recheck.Value;
    }

    async Task<OnBehalfGrant> CheckAndRemember(OnBehalfSession session, ClientPrincipal actor, C.OnBehalf settings)
    {
        try
        {
            var grant = await grants.Check(session, actor, CancellationToken.None);
            if (grant.IsLive)
            {
                ledger.Remember(session.SessionId, grant, FreshUntil(session, grant, settings));
            }

            return grant;
        }
        finally
        {
            _rechecks.TryRemove(session.SessionId, out _);
        }
    }

    async Task<OnBehalfResolution> Ended(HttpContext context, OnBehalfSession session, OnBehalfSessionEndReason reason)
    {
        await EndSession(context, session, reason);
        return new(OnBehalfResolutionStatus.Ended, Reason: reason);
    }

    async Task<OnBehalfEndStatus> EndSession(HttpContext context, OnBehalfSession session, OnBehalfSessionEndReason reason)
    {
        OnBehalfSessionCookie.Delete(context);
        ExpireIdentityState(context);

        // Only the call that ends the session notifies, so concurrent requests discovering the same revoked grant tell
        // the application once. The notification outlives the request that triggered it: an actor closing the tab is
        // not a reason for the application never to hear the session ended.
        if (!ledger.TryMarkEnded(session.SessionId, reason, session.ExpiresAt))
        {
            return OnBehalfEndStatus.Ended;
        }

        logger.SessionEnded(session.SessionId, reason.ToWireValue());
        return await notifier.Ended(session, reason, ledger.Now, CancellationToken.None)
            ? OnBehalfEndStatus.Ended
            : OnBehalfEndStatus.EndedWithoutNotification;
    }
}
