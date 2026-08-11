// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Text;

namespace Cratis.AuthProxy;

/// <summary>
/// Writes the one answer a request that has earned no answer ever receives.
/// </summary>
/// <remarks>
/// Every refusal has to be the same refusal — same status, same headers, same bytes — because anything that
/// varies is an answer. A different status for a path that exists, a <c>WWW-Authenticate</c> where a
/// challenge would have started, an <c>Allow</c> listing the methods a route accepts, a <c>Location</c>
/// pointing at a provider, a cookie issued on the way out: each of those is a question answered for a
/// caller who has presented nothing.
/// <para>
/// It lives at the root rather than beside the admission gate because it is not only admission's refusal.
/// The management listener refuses with it too, so that probing a deployment's public listener for a health
/// path is answered exactly as probing it for anything else is — a refusal that differs is a refusal that
/// says an AuthProxy is here and that it has a management listener.
/// </para>
/// <para>
/// The sameness claimed here is of <em>content</em>, not of every observable. A refusal costs what the work
/// ahead of it cost, and that work is not the same for every route: a presentation reaching the capability
/// verifier takes a round-trip a refused path never takes, and an over-length body is refused before the
/// round-trip starts. Timing is therefore measurably distinguishable and is deliberately not addressed
/// here — the claim is that no response ever <em>says</em> anything, not that none can be timed.
/// </para>
/// <para>
/// It is deliberately <em>not</em> written through <see cref="ErrorPages.IErrorPageProvider"/>. That
/// provider injects a <c>&lt;base href="/_pages/"&gt;</c> so a branded page can load its assets, and
/// <c>/_pages</c> is one of the things a closed deployment closes — so a branded refusal would render
/// without its assets and, worse, would be a distinguishable answer: it says an AuthProxy is here and that
/// it has pages.
/// </para>
/// </remarks>
public static class UniformDenial
{
    /// <summary>
    /// The exact body every refusal carries. Fixed, asset-free and unbranded — it describes nothing about
    /// what is running, what is configured, or what was asked for.
    /// </summary>
    public const string Body = "Not Found";

    /// <summary>
    /// The exact content type every refusal carries.
    /// </summary>
    public const string ContentType = "text/plain; charset=utf-8";

    /// <summary>
    /// The exact cache directive every refusal carries.
    /// </summary>
    /// <remarks>
    /// A refusal is a statement about the caller, not about the resource, so a shared cache that stored one
    /// would go on serving it to callers who would have been answered — and, worse, a cache that stored an
    /// <em>answer</em> under the same key would serve it to callers who have presented nothing. Saying
    /// <c>no-store</c> on the refusal is the half of that this type owns.
    /// </remarks>
    public const string CacheControl = "no-store";

    static readonly byte[] _bytes = Encoding.UTF8.GetBytes(Body);

    /// <summary>
    /// Writes the refusal.
    /// </summary>
    /// <param name="context">The <see cref="HttpContext"/> to answer.</param>
    /// <returns>A <see cref="Task"/> representing the asynchronous operation.</returns>
    /// <remarks>
    /// Headers already on the response are cleared rather than added to, so nothing an earlier decision
    /// queued — a cookie, a challenge header — can survive into a refusal and make it distinguishable.
    /// </remarks>
    public static async Task Write(HttpContext context)
    {
        if (context.Response.HasStarted)
        {
            return;
        }

        context.Response.Headers.Clear();
        context.Response.StatusCode = StatusCodes.Status404NotFound;
        context.Response.ContentType = ContentType;
        context.Response.ContentLength = _bytes.Length;
        context.Response.Headers.CacheControl = CacheControl;

        // A HEAD response carries the headers of the GET it stands for and none of its body. Writing the
        // body anyway would leave the two answers differing in more than the protocol requires.
        if (HttpMethods.IsHead(context.Request.Method))
        {
            return;
        }

        await context.Response.Body.WriteAsync(_bytes, context.RequestAborted);
    }
}
