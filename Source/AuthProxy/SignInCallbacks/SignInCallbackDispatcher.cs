// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Collections.Concurrent;
using System.Diagnostics.CodeAnalysis;
using System.Security.Claims;
using Cratis.AuthProxy.Authentication;
using Cratis.AuthProxy.ForwardedIdentity;
using Cratis.AuthProxy.Identity;
using Cratis.AuthProxy.ReverseProxy;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.Extensions.Options;
using C = Cratis.AuthProxy.Configuration;

namespace Cratis.AuthProxy.SignInCallbacks;

/// <summary>
/// Decides when a service is told about a user.
/// </summary>
/// <param name="config">The auth proxy configuration monitor.</param>
/// <param name="queue">The queue the callbacks are handed to.</param>
/// <param name="services">The service provider, from which the tenant resolver is taken when a sign-in completes before a tenant has been resolved for the request.</param>
/// <param name="timeProvider">The time provider.</param>
/// <param name="logger">The logger.</param>
/// <remarks>
/// A user is remembered per service in memory: a user signed in or reported as returned within the service's interval
/// is not reported as returned again. There is no new store. The memory is per replica and does not survive a restart,
/// so with several replicas, or after a restart, a service can be told about the same user more than once in an
/// interval — the receiving endpoint has to be idempotent.
/// </remarks>
public class SignInCallbackDispatcher(
    IOptionsMonitor<C.AuthProxy> config,
    ISignInCallbackQueue queue,
    IServiceProvider services,
    TimeProvider timeProvider,
    ILogger<SignInCallbackDispatcher> logger) : ISignInCallbackDispatcher
{
    /// <summary>
    /// The number of remembered users beyond which expired entries are cleared out.
    /// </summary>
    public const int PruneThreshold = 4096;

    readonly ConcurrentDictionary<(string Service, string Subject), DateTimeOffset> _seen = new();

    /// <inheritdoc/>
    public void SignedIn(HttpContext context, ClaimsPrincipal user, string scheme, AuthenticationProperties? properties)
    {
        string? serviceName = null;
        try
        {
            var current = config.CurrentValue;
            if (!current.Services.Values.Any(_ => _.SignInCallback is not null))
            {
                return;
            }

            var routed = ServiceRoutes.Resolve(context.Request, current);
            if (routed?.Service.SignInCallback is not { } callback || routed.Service.Backend is not { } backend)
            {
                return;
            }

            serviceName = routed.Name;

            // The principal is described the way the next proxied request will describe it, against the cookie session
            // that is about to carry it.
            var principal = context.BuildClientPrincipal(user, CookieAuthenticationDefaults.AuthenticationScheme, properties);
            if (!HasIdentity(principal))
            {
                logger.CallbackWithoutIdentity(serviceName, SignInCallbackKind.SignedIn);
                return;
            }

            var tenant = ResolveTenant(context);
            var now = timeProvider.GetUtcNow();

            // A real sign-in always counts, and it starts the interval over: the request that follows it is not a return.
            Remember(serviceName, principal.UserId, now + callback.Interval, now);
            var evidence = routed.Service.ForwardedIdentity?.Version == "v2" ? BrowserSessionEvidence.Read(context, user, properties) : null;
            Enqueue(new(serviceName, backend.BaseUrl.TrimEnd('/') + callback.Path, callback.Timeout, callback.Secret, SignInCallbackKind.SignedIn, principal, tenant, now)
            {
                TrustedContext = Snapshot(evidence, now)
            });
        }
        catch (Exception ex)
        {
            logger.CallbackNotPrepared(ex, serviceName ?? "unknown", SignInCallbackKind.SignedIn);
        }
    }

    /// <inheritdoc/>
    public void Returned(HttpContext context, string serviceName, C.Service service, ClientPrincipal principal, string? tenant)
    {
        try
        {
            if (string.IsNullOrWhiteSpace(principal.UserId)) return;
            if (service.SignInCallback is not { } callback || service.Backend is not { } backend)
            {
                return;
            }

            var now = timeProvider.GetUtcNow();
            if (!TryClaim(serviceName, principal.UserId, now, callback.Interval))
            {
                return;
            }

            var evidence = service.ForwardedIdentity?.Version == "v2" ? BrowserSessionEvidence.For(context) : null;
            Enqueue(new(serviceName, backend.BaseUrl.TrimEnd('/') + callback.Path, callback.Timeout, callback.Secret, SignInCallbackKind.Returned, principal, tenant, now)
            {
                TrustedContext = Snapshot(evidence, now)
            });
        }
        catch (Exception ex)
        {
            logger.CallbackNotPrepared(ex, serviceName, SignInCallbackKind.Returned);
        }
    }

    static bool HasIdentity([NotNullWhen(true)] ClientPrincipal? principal) => principal is not null && !string.IsNullOrWhiteSpace(principal.UserId);

    static ForwardedIdentityTrustedContext? Snapshot(ForwardedIdentityTrustedContext? evidence, DateTimeOffset now) => evidence is null
        ? null
        : evidence with { SnapshotExpiresUtc = now.AddSeconds(60) };

    string? ResolveTenant(HttpContext context) => services.GetService<ITenantResolver>() is { } tenantResolver && tenantResolver.TryResolve(context, out string tenantId)
        ? tenantId
        : null;

    bool TryClaim(string serviceName, string subject, DateTimeOffset now, TimeSpan interval)
    {
        var key = (serviceName, subject);
        while (true)
        {
            if (_seen.TryGetValue(key, out var expires))
            {
                if (expires > now)
                {
                    return false;
                }

                if (_seen.TryUpdate(key, now + interval, expires))
                {
                    return true;
                }

                continue;
            }

            if (_seen.TryAdd(key, now + interval))
            {
                Prune(now);
                return true;
            }
        }
    }

    void Remember(string serviceName, string subject, DateTimeOffset expires, DateTimeOffset now)
    {
        _seen[(serviceName, subject)] = expires;
        Prune(now);
    }

    void Prune(DateTimeOffset now)
    {
        if (_seen.Count <= PruneThreshold)
        {
            return;
        }

        foreach (var entry in _seen.Where(_ => _.Value <= now))
        {
            _seen.TryRemove(entry);
        }
    }

    void Enqueue(SignInCallbackRequest request)
    {
        if (!queue.TryEnqueue(request))
        {
            logger.CallbackDropped(request.ServiceName, request.Kind);
        }
    }
}
