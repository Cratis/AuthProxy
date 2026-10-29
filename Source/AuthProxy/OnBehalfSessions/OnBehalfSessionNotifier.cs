// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.Extensions.Options;
using C = Cratis.AuthProxy.Configuration;

namespace Cratis.AuthProxy.OnBehalfSessions;

/// <summary>
/// Posts the session notifications to the application:
/// <c language="text">POST {backend}/.cratis/on-behalf/sessions/started</c> and <c language="text">…/ended</c>.
/// </summary>
/// <param name="config">The auth proxy configuration monitor.</param>
/// <param name="attestations">The issuer of the signed token each notification carries.</param>
/// <param name="httpClientFactory">The HTTP client factory.</param>
/// <param name="logger">The logger.</param>
/// <remarks>
/// Each notification is signed over its exact body bytes, so reaching the application's endpoint is not enough to
/// make it record a session that never happened. Every failure is reported through the return value and never
/// thrown: what a failure means is the caller's decision, because a failed start notification refuses the session
/// while a failed end notification cannot keep one alive.
/// </remarks>
public sealed class OnBehalfSessionNotifier(
    IOptionsMonitor<C.AuthProxy> config,
    IOnBehalfAttestations attestations,
    IHttpClientFactory httpClientFactory,
    ILogger<OnBehalfSessionNotifier> logger) : IOnBehalfSessionNotifier
{
    /// <inheritdoc/>
    public Task<bool> Started(OnBehalfSession session, OnBehalfGrant grant, CancellationToken cancellationToken) =>
        Post(
            WellKnownPaths.OnBehalfSessionStarted,
            OnBehalfAttestationClaims.SessionStartedPurpose,
            session,
            new OnBehalfSessionStartedNotification(
                session.SessionId,
                session.Tenant,
                session.Issue,
                session.Subject,
                OnBehalfActorNotification.From(session.Actor),
                session.StartedAt,
                session.ExpiresAt,
                grant.ValidUntil),
            cancellationToken);

    /// <inheritdoc/>
    public Task<bool> Ended(OnBehalfSession session, OnBehalfSessionEndReason reason, DateTimeOffset endedAt, CancellationToken cancellationToken) =>
        Post(
            WellKnownPaths.OnBehalfSessionEnded,
            OnBehalfAttestationClaims.SessionEndedPurpose,
            session,
            new OnBehalfSessionEndedNotification(
                session.SessionId,
                session.Tenant,
                session.Issue,
                session.Subject,
                OnBehalfActorNotification.From(session.Actor),
                session.StartedAt,
                endedAt,
                reason.ToWireValue()),
            cancellationToken);

    async Task<bool> Post<TNotification>(string path, string purpose, OnBehalfSession session, TNotification notification, CancellationToken cancellationToken)
    {
        var current = config.CurrentValue;
        if (!OnBehalfApplication.TryResolve(current, path, out var target))
        {
            logger.SessionNotificationNotConfigured(path);
            return false;
        }

        // The digest is taken from the bytes the request will actually carry, not from the object they were built out
        // of, and a notification that cannot be signed is not sent at all — never downgraded to an unsigned call.
        using var content = JsonContent.Create(notification);
        var body = await content.ReadAsByteArrayAsync(cancellationToken);
        if (!attestations.TryIssueForCall(purpose, session, HttpMethod.Post, target, body, out var token))
        {
            logger.SessionNotificationCouldNotBeSigned(path);
            return false;
        }

        using var request = new HttpRequestMessage(HttpMethod.Post, target) { Content = content };
        OnBehalfApplication.AddHeaders(request, session, null, token);

        using var bounded = OnBehalfApplication.Bounded(current, cancellationToken);
        try
        {
            using var client = httpClientFactory.CreateClient();
            using var response = await client.SendAsync(request, bounded.Token);
            if (!response.IsSuccessStatusCode)
            {
                logger.SessionNotificationUnsuccessful(path, (int)response.StatusCode);
                return false;
            }

            logger.SessionNotified(path);
            return true;
        }
        catch (Exception exception) when (exception is HttpRequestException or OperationCanceledException or IOException)
        {
            logger.SessionNotificationFailed(exception, path);
            return false;
        }
    }
}
