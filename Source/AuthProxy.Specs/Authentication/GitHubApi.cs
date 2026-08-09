// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Net;
using System.Text;

namespace Cratis.AuthProxy.Authentication;

/// <summary>
/// A stand-in for GitHub's REST API that records what was asked of it.
/// </summary>
/// <remarks>
/// Responses are produced per request rather than handed over up front, because a paged read disposes each
/// response as it goes and asks for the next page from the previous one's <c>Link</c> header — a fixed
/// response would be read once and disposed before the second page needed it.
/// </remarks>
/// <param name="respond">Produces the response for a requested URL.</param>
class GitHubApi(Func<Uri, HttpResponseMessage> respond) : HttpMessageHandler
{
    readonly List<Uri> _requested = [];

    /// <summary>Gets every URL that was requested, in order.</summary>
    public IReadOnlyList<Uri> Requested => _requested;

    /// <summary>
    /// Builds a JSON array response, optionally linking a next page.
    /// </summary>
    /// <param name="json">The JSON array body.</param>
    /// <param name="nextPage">The absolute URL of the next page, when there is one.</param>
    /// <returns>The response.</returns>
    public static HttpResponseMessage Page(string json, string? nextPage = null)
    {
        var response = new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent(json, Encoding.UTF8, "application/json"),
        };

        if (nextPage is not null)
        {
            response.Headers.TryAddWithoutValidation("Link", $"<{nextPage}>; rel=\"next\", <{nextPage}>; rel=\"last\"");
        }

        return response;
    }

    /// <summary>
    /// Builds a refusal, as GitHub answers a token without the scope to read organization membership.
    /// </summary>
    /// <returns>The response.</returns>
    public static HttpResponseMessage Refused() => new(HttpStatusCode.Forbidden);

    /// <summary>
    /// Creates the client the enricher reads through.
    /// </summary>
    /// <returns>A client backed by this handler.</returns>
    public HttpClient CreateClient() => new(this, disposeHandler: false);

    /// <inheritdoc/>
    protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        _requested.Add(request.RequestUri!);
        return Task.FromResult(respond(request.RequestUri!));
    }
}
