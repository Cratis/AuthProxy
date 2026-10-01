// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Net;

namespace Cratis.AuthProxy.AccessTokens.given;

/// <summary>
/// A stand-in identity-provider token endpoint that records each form it receives and answers with whatever the spec
/// queued.
/// </summary>
public class TokenEndpoint : HttpMessageHandler
{
    /// <summary>
    /// Gets the forms received, in order.
    /// </summary>
    public List<Dictionary<string, string>> Received { get; } = [];

    /// <summary>
    /// Gets or sets how the endpoint answers the next request.
    /// </summary>
    public Func<HttpResponseMessage> Answer { get; set; } = () => Bearer("access-token", 3600);

    /// <summary>
    /// Builds a successful bearer token answer.
    /// </summary>
    /// <param name="accessToken">The access token.</param>
    /// <param name="expiresIn">The lifetime in seconds.</param>
    /// <param name="refreshToken">An optional rotated refresh token.</param>
    /// <returns>The response.</returns>
    public static HttpResponseMessage Bearer(string accessToken, int expiresIn, string? refreshToken = null)
    {
        var rotation = refreshToken is null ? string.Empty : $$""","refresh_token":"{{refreshToken}}" """.TrimEnd();
        return Json(HttpStatusCode.OK, $$"""{"access_token":"{{accessToken}}","token_type":"Bearer","expires_in":{{expiresIn}}{{rotation}}}""");
    }

    /// <summary>
    /// Builds an OAuth error answer.
    /// </summary>
    /// <param name="error">The error code.</param>
    /// <returns>The response.</returns>
    public static HttpResponseMessage Error(string error) => Json(HttpStatusCode.BadRequest, $$"""{"error":"{{error}}"}""");

    /// <summary>
    /// Builds a JSON answer.
    /// </summary>
    /// <param name="status">The status code.</param>
    /// <param name="json">The body.</param>
    /// <returns>The response.</returns>
    public static HttpResponseMessage Json(HttpStatusCode status, string json) =>
        new(status) { Content = new StringContent(json, System.Text.Encoding.UTF8, "application/json") };

    /// <inheritdoc/>
    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        var form = await request.Content!.ReadAsStringAsync(cancellationToken);
        Received.Add(Microsoft.AspNetCore.WebUtilities.QueryHelpers.ParseQuery(form).ToDictionary(_ => _.Key, _ => _.Value.ToString(), StringComparer.Ordinal));
        return Answer();
    }
}
