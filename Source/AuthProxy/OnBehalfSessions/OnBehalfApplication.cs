// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.Identity;
using C = Cratis.AuthProxy.Configuration;

namespace Cratis.AuthProxy.OnBehalfSessions;

/// <summary>
/// Resolves and prepares the calls AuthProxy makes to the application about on-behalf sessions.
/// </summary>
static class OnBehalfApplication
{
    /// <summary>
    /// Resolves the absolute address of one of the application's on-behalf endpoints.
    /// </summary>
    /// <param name="config">The current configuration.</param>
    /// <param name="path">The well-known path on the application's backend.</param>
    /// <param name="address">The absolute address.</param>
    /// <returns><see langword="true"/> when the configured service declares a usable backend; otherwise <see langword="false"/>.</returns>
    public static bool TryResolve(C.AuthProxy config, string path, out Uri address)
    {
        address = default!;
        var serviceName = config.OnBehalf?.Service;
        if (string.IsNullOrWhiteSpace(serviceName)
            || !config.Services.TryGetValue(serviceName, out var service)
            || string.IsNullOrWhiteSpace(service.Backend?.BaseUrl))
        {
            return false;
        }

        return Uri.TryCreate(service.Backend.BaseUrl.TrimEnd('/') + path, UriKind.Absolute, out address!);
    }

    /// <summary>
    /// Adds the headers every call about a session carries: the tenant, the actor and the signed token.
    /// </summary>
    /// <param name="request">The outgoing request.</param>
    /// <param name="session">The session the call is about.</param>
    /// <param name="actor">The actor's client principal, when it is known; otherwise the actor is described from the session.</param>
    /// <param name="token">The signed token.</param>
    public static void AddHeaders(HttpRequestMessage request, OnBehalfSession session, ClientPrincipal? actor, string token)
    {
        var tenant = HeaderValue.ToTransportValue(session.Tenant);
        request.Headers.Add(Headers.TenantId, tenant);
        request.Headers.Add(Headers.LegacyTenantId, tenant);
        request.Headers.Add(Headers.OnBehalfActor, (actor ?? Describe(session.Actor)).ToBase64());
        request.Headers.Authorization = new("Bearer", token);
    }

    /// <summary>
    /// Describes an actor known only from a session as a client principal.
    /// </summary>
    /// <param name="actor">The actor.</param>
    /// <returns>A <see cref="ClientPrincipal"/> carrying the actor's identity provider, subject and name.</returns>
    public static ClientPrincipal Describe(OnBehalfActor actor) => new()
    {
        IdentityProvider = actor.IdentityProvider,
        UserId = actor.UserId,
        UserDetails = actor.UserDetails,
    };

    /// <summary>
    /// Creates a cancellation scope bounded by the configured timeout.
    /// </summary>
    /// <param name="config">The current configuration.</param>
    /// <param name="cancellationToken">The caller's request lifetime.</param>
    /// <returns>The linked <see cref="CancellationTokenSource"/>.</returns>
    public static CancellationTokenSource Bounded(C.AuthProxy config, CancellationToken cancellationToken)
    {
        var source = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        source.CancelAfter(config.OnBehalf?.Timeout ?? C.OnBehalf.DefaultTimeout);
        return source;
    }
}
