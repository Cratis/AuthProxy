// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Net.Http.Headers;

namespace Cratis.AuthProxy.Authentication;

/// <summary>
/// Reads a paged GitHub REST collection and projects each entry to a single string.
/// </summary>
/// <remarks>
/// GitHub pages every collection endpoint and links the next page from a <c>Link</c> header rather than
/// from the body, so a single request answers "the first hundred organizations", which for authorization
/// is a different question from the one being asked. Following the links is what makes membership in the
/// hundred-and-first organization count.
/// </remarks>
internal static class GitHubPagedResourceReader
{
    /// <summary>The page size requested; GitHub's maximum, so the common case is one request.</summary>
    const int PageSize = 100;

    /// <summary>
    /// The number of pages followed before stopping.
    /// </summary>
    /// <remarks>
    /// A bound rather than "until GitHub stops linking", because this runs inside a sign-in handshake a
    /// person is waiting on, and every claim collected ends up in the authentication cookie. Five pages is
    /// five hundred organizations or teams, far past any plausible allow-list, and the cost of stopping
    /// there is a requirement that is not satisfied — the fail-closed direction.
    /// </remarks>
    const int MaxPages = 5;

    const string LinkHeader = "Link";
    const string NextRelation = "rel=\"next\"";
    const string MediaType = "application/vnd.github+json";

    /// <summary>
    /// Reads every page of a collection, projecting each entry.
    /// </summary>
    /// <param name="client">The HTTP client to read through.</param>
    /// <param name="accessToken">The access token to present.</param>
    /// <param name="resource">The absolute URL of the collection.</param>
    /// <param name="select">Projects one entry to the value to keep, or <see langword="null"/> to skip it.</param>
    /// <param name="logger">The logger used to report a failed read.</param>
    /// <param name="cancellationToken">A <see cref="CancellationToken"/> for the operation.</param>
    /// <returns>The projected values, in the order returned.</returns>
    /// <remarks>
    /// Never throws: a failure returns what was read before it. The caller is completing a sign-in, and a
    /// user who cannot be signed in at all is a worse outcome than one signed in without the claims — which
    /// leaves them refused by the gate, with an explanation, rather than staring at a broken login.
    /// </remarks>
    internal static async Task<IEnumerable<string>> Read(
        HttpClient client,
        string accessToken,
        Uri resource,
        Func<JsonElement, string?> select,
        ILogger logger,
        CancellationToken cancellationToken)
    {
        var values = new List<string>();
        var next = WithPageSize(resource);

        try
        {
            for (var page = 0; page < MaxPages && next is not null; page++)
            {
                using var request = BuildRequest(next, accessToken);
                using var response = await client.SendAsync(request, cancellationToken);

                if (!response.IsSuccessStatusCode)
                {
                    logger.MembershipReadFailed(resource.AbsolutePath, (int)response.StatusCode);
                    break;
                }

                using var document = JsonDocument.Parse(await response.Content.ReadAsStringAsync(cancellationToken));
                if (document.RootElement.ValueKind != JsonValueKind.Array)
                {
                    break;
                }

                foreach (var element in document.RootElement.EnumerateArray())
                {
                    var value = select(element);
                    if (!string.IsNullOrWhiteSpace(value))
                    {
                        values.Add(value);
                    }
                }

                next = NextPage(response, resource);
            }
        }
        catch (HttpRequestException ex)
        {
            logger.MembershipReadUnavailable(resource.AbsolutePath, ex);
        }
        catch (JsonException ex)
        {
            logger.MembershipReadUnreadable(resource.AbsolutePath, ex);
        }
        catch (OperationCanceledException)
        {
            // The caller went away mid-handshake. Nothing to report and nothing to sign in.
        }

        return values;
    }

    static HttpRequestMessage BuildRequest(Uri url, string accessToken)
    {
        var request = new HttpRequestMessage(HttpMethod.Get, url);
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);
        request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue(MediaType));
        request.Headers.UserAgent.Add(new ProductInfoHeaderValue("Cratis-AuthProxy", "1.0"));

        return request;
    }

    static Uri WithPageSize(Uri resource) =>
        new UriBuilder(resource)
        {
            Query = string.IsNullOrEmpty(resource.Query)
                ? $"per_page={PageSize}"
                : $"{resource.Query.TrimStart('?')}&per_page={PageSize}"
        }.Uri;

    /// <summary>
    /// Resolves the next page from the response's <c>Link</c> header.
    /// </summary>
    /// <param name="response">The response just read.</param>
    /// <param name="origin">The collection URL the read started from.</param>
    /// <returns>The next page, or <see langword="null"/> when there is none.</returns>
    /// <remarks>
    /// The link is a URL out of a response, so it is followed only when it stays on the host the read
    /// started from. Without that check a compromised or spoofed response could walk the proxy's
    /// authenticated back channel — carrying the user's access token — to a host of its choosing.
    /// </remarks>
    static Uri? NextPage(HttpResponseMessage response, Uri origin)
    {
        if (!response.Headers.TryGetValues(LinkHeader, out var headers))
        {
            return null;
        }

        foreach (var candidate in headers.SelectMany(header => header.Split(',')))
        {
            var segments = candidate.Split(';');
            if (segments.Length < 2 || !segments.Any(_ => _.Contains(NextRelation, StringComparison.OrdinalIgnoreCase)))
            {
                continue;
            }

            if (Uri.TryCreate(segments[0].Trim().Trim('<', '>'), UriKind.Absolute, out var next)
                && string.Equals(next.Scheme, origin.Scheme, StringComparison.OrdinalIgnoreCase)
                && string.Equals(next.Authority, origin.Authority, StringComparison.OrdinalIgnoreCase))
            {
                return next;
            }
        }

        return null;
    }
}
