// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.Net.Http.Headers;

namespace Cratis.AuthProxy.Management;

/// <summary>
/// Writes what the management listener answers.
/// </summary>
/// <param name="readiness">The <see cref="IReadinessCheck"/> consulted for readiness.</param>
/// <remarks>
/// Every answer is a fixed, bounded body naming nothing about the deployment — no provider, tenant,
/// backend address, filesystem path, key identifier, version or assembly — and a failing readiness answer
/// discloses no more than a succeeding one. A management endpoint is the one surface that is reachable
/// without a credential by design, so anything it says is said to whoever can reach the port.
/// <para>
/// Liveness consults nothing at all: no dependency is resolved and no I/O is performed, so it answers
/// <c>200</c> for as long as the request loop is servicing requests, including while every dependency is
/// unreachable. That is what stops an orchestrator restarting a healthy proxy during somebody else's
/// outage.
/// </para>
/// </remarks>
internal sealed class ManagementEndpoints(IReadinessCheck readiness)
{
    /// <summary>The body of a liveness answer.</summary>
    internal const string LiveBody = "live";

    /// <summary>The body of a positive readiness answer.</summary>
    internal const string ReadyBody = "ready";

    /// <summary>The body of a negative readiness answer.</summary>
    internal const string NotReadyBody = "not ready";

    /// <summary>
    /// Answers a request the management listener owns.
    /// </summary>
    /// <param name="context">The <see cref="HttpContext"/> of the request.</param>
    /// <param name="disposition">What the request was decided to be.</param>
    /// <returns>Awaitable task.</returns>
    public async Task Answer(HttpContext context, ManagementDisposition disposition)
    {
        if (disposition == ManagementDisposition.Live)
        {
            await Write(context, StatusCodes.Status200OK, LiveBody);
            return;
        }

        if (disposition != ManagementDisposition.Ready)
        {
            await Write(context, StatusCodes.Status404NotFound, string.Empty);
            return;
        }

        var ready = await readiness.IsReady(context.RequestAborted);
        await Write(
            context,
            ready ? StatusCodes.Status200OK : StatusCodes.Status503ServiceUnavailable,
            ready ? ReadyBody : NotReadyBody);
    }

    static Task Write(HttpContext context, int statusCode, string body)
    {
        var response = context.Response;

        response.StatusCode = statusCode;

        // Nothing upstream of this can have written them, because the management middleware is the first
        // statement in the pipeline. Removed anyway, so that inserting anything ahead of it later cannot
        // quietly turn a health answer into a challenge or hand out a session.
        response.Headers.Remove(HeaderNames.WWWAuthenticate);
        response.Headers.Remove(HeaderNames.SetCookie);

        response.Headers.CacheControl = "no-store";
        response.ContentType = "text/plain; charset=utf-8";

        return response.WriteAsync(body, context.RequestAborted);
    }
}
