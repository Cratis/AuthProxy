// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using C = Cratis.AuthProxy.Configuration;

namespace Cratis.AuthProxy.OnBehalfSessions;

/// <summary>
/// Answers AuthProxy's own on-behalf endpoints under <see cref="WellKnownPaths.OnBehalf"/>.
/// </summary>
/// <remarks>
/// Every answer is JSON and <c language="text">Cache-Control: no-store</c>. A refusal carries <c language="text">{ "error": "…" }</c>
/// with a stable code, so a support tool can tell "no grant" from "try again".
/// <para>
/// Starting a session requires a JSON body. A cross-site HTML form cannot send one without a CORS preflight that
/// AuthProxy never answers, so another site cannot make a support person's browser start a session.
/// </para>
/// </remarks>
public static class OnBehalfEndpoints
{
    const string StartSegment = "/start";
    const string EndSegment = "/end";

    /// <summary>
    /// Answers one request under <see cref="WellKnownPaths.OnBehalf"/>.
    /// </summary>
    /// <param name="context">The current <see cref="HttpContext"/>.</param>
    /// <param name="remaining">The path below <see cref="WellKnownPaths.OnBehalf"/>.</param>
    /// <param name="config">The current configuration.</param>
    /// <param name="sessions">The on-behalf sessions.</param>
    /// <returns>A <see cref="Task"/> representing the asynchronous operation.</returns>
    public static async Task Handle(HttpContext context, PathString remaining, C.AuthProxy config, IOnBehalfSessions sessions)
    {
        context.Response.Headers.CacheControl = "no-store";
        if (config.OnBehalf is null)
        {
            await Refuse(context, StatusCodes.Status404NotFound, "not-enabled");
            return;
        }

        var segment = remaining.Value?.TrimEnd('/') ?? string.Empty;
        var method = context.Request.Method;
        switch (segment)
        {
            case "" when HttpMethods.IsGet(method) || HttpMethods.IsHead(method):
                await Current(context, sessions);
                return;

            case StartSegment when HttpMethods.IsPost(method):
                await Start(context, sessions);
                return;

            case EndSegment when HttpMethods.IsPost(method):
                await End(context, sessions);
                return;

            case "" or StartSegment or EndSegment:
                context.Response.StatusCode = StatusCodes.Status405MethodNotAllowed;
                return;

            default:
                context.Response.StatusCode = StatusCodes.Status404NotFound;
                return;
        }
    }

    static async Task Start(HttpContext context, IOnBehalfSessions sessions)
    {
        if (!context.Request.HasJsonContentType())
        {
            await Refuse(context, StatusCodes.Status415UnsupportedMediaType, "json-required");
            return;
        }

        OnBehalfStartRequest? request;
        try
        {
            request = await context.Request.ReadFromJsonAsync<OnBehalfStartRequest>(context.RequestAborted);
        }
        catch (JsonException)
        {
            request = null;
        }

        if (request is null)
        {
            await Refuse(context, StatusCodes.Status400BadRequest, "invalid-request");
            return;
        }

        var result = await sessions.Start(context, request);
        switch (result.Status)
        {
            case OnBehalfStartStatus.Started:
                var session = result.Session!;
                await context.Response.WriteAsJsonAsync(new
                {
                    sessionId = session.SessionId,
                    tenant = session.Tenant,
                    subject = session.Subject,
                    issue = session.Issue,
                    startedAt = session.StartedAt,
                    expiresAt = session.ExpiresAt,
                    grantValidUntil = result.Grant!.ValidUntil,
                });
                return;

            case OnBehalfStartStatus.NotEnabled:
                await Refuse(context, StatusCodes.Status404NotFound, "not-enabled");
                return;

            case OnBehalfStartStatus.Unauthenticated:
                await Refuse(context, StatusCodes.Status401Unauthorized, "unauthenticated");
                return;

            case OnBehalfStartStatus.Invalid:
                await Refuse(context, StatusCodes.Status400BadRequest, "invalid-request");
                return;

            case OnBehalfStartStatus.Forbidden:
                await Refuse(context, StatusCodes.Status403Forbidden, "actor-not-permitted");
                return;

            case OnBehalfStartStatus.Conflict:
                await Refuse(context, StatusCodes.Status409Conflict, "session-active");
                return;

            case OnBehalfStartStatus.NotGranted:
                await Refuse(context, StatusCodes.Status403Forbidden, "not-granted");
                return;

            default:
                await Refuse(context, StatusCodes.Status503ServiceUnavailable, "unavailable");
                return;
        }
    }

    static async Task End(HttpContext context, IOnBehalfSessions sessions)
    {
        var status = await sessions.End(context, OnBehalfSessionEndReason.EndedByActor);
        if (status == OnBehalfEndStatus.EndedWithoutNotification)
        {
            await Refuse(context, StatusCodes.Status502BadGateway, "ended-not-acknowledged");
            return;
        }

        context.Response.StatusCode = StatusCodes.Status204NoContent;
    }

    static async Task Current(HttpContext context, IOnBehalfSessions sessions)
    {
        var resolution = await sessions.Resolve(context);
        switch (resolution.Status)
        {
            case OnBehalfResolutionStatus.Active:
                var active = resolution.Context!;
                await context.Response.WriteAsJsonAsync(new
                {
                    sessionId = active.Session.SessionId,
                    tenant = active.Session.Tenant,
                    subject = active.Session.Subject,
                    issue = active.Session.Issue,
                    startedAt = active.Session.StartedAt,
                    expiresAt = active.Session.ExpiresAt,
                    represented = new
                    {
                        identityProvider = active.Represented.IdentityProvider,
                        userId = active.Represented.UserId,
                        userDetails = active.Represented.UserDetails,
                    },
                });
                return;

            case OnBehalfResolutionStatus.Ended:
                context.Response.Headers[Headers.OnBehalfEnded] = resolution.Reason!.Value.ToWireValue();
                await Refuse(context, StatusCodes.Status404NotFound, "no-session");
                return;

            case OnBehalfResolutionStatus.Unavailable:
                await Refuse(context, StatusCodes.Status503ServiceUnavailable, "unavailable");
                return;

            default:
                await Refuse(context, StatusCodes.Status404NotFound, "no-session");
                return;
        }
    }

    static Task Refuse(HttpContext context, int statusCode, string error)
    {
        context.Response.StatusCode = statusCode;
        return context.Response.WriteAsJsonAsync(new { error });
    }
}
