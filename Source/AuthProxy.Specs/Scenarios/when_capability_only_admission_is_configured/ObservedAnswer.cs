// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Scenarios.when_capability_only_admission_is_configured;

/// <summary>
/// Everything a caller can observe about one answer: the status, every header, and the bytes.
/// </summary>
/// <param name="Route">The path that was asked for.</param>
/// <param name="Method">The method it was asked with.</param>
/// <param name="StatusCode">The status that came back.</param>
/// <param name="Headers">Every header that came back, normalized and sorted.</param>
/// <param name="Body">The bytes that came back.</param>
/// <remarks>
/// Comparing statuses alone is the mistake this type exists to prevent: a gate can answer <c>404</c>
/// everywhere and still describe the deployment through an <c>Allow</c>, a <c>WWW-Authenticate</c>, a
/// content type or a body length that varies with the route.
/// <para>
/// <c>Date</c> is excluded because it is a clock reading rather than anything about the request. Everything
/// else — including <c>Content-Length</c> and <c>Content-Type</c> — is compared exactly.
/// </para>
/// </remarks>
public sealed record ObservedAnswer(string Route, string Method, int StatusCode, string Headers, string Body)
{
    /// <summary>
    /// The headers whose presence would answer a question the caller has not earned an answer to.
    /// </summary>
    public static readonly string[] TellTaleHeaders = ["Allow", "Retry-After", "WWW-Authenticate", "Location", "Set-Cookie"];

    /// <summary>
    /// Gets everything about the answer other than which request produced it.
    /// </summary>
    public string Shape => $"{StatusCode}\n{Headers}\n{Body}";

    /// <summary>
    /// Gets what the answer looks like to a caller who cannot read the body — every method's answer has to
    /// agree here even where the protocol forbids the body itself.
    /// </summary>
    public string HeaderShape => $"{StatusCode}\n{Headers}";

    /// <summary>
    /// Asks one request and records everything about the answer.
    /// </summary>
    /// <param name="client">The client to ask with.</param>
    /// <param name="route">The path to ask for.</param>
    /// <param name="method">The method to ask with.</param>
    /// <returns>The observed answer.</returns>
    public static async Task<ObservedAnswer> Capture(HttpClient client, string route, HttpMethod method)
    {
        using var request = new HttpRequestMessage(method, route);
        using var response = await client.SendAsync(request);

        var headers = response.Headers
            .Concat(response.Content.Headers)
            .Where(header => !string.Equals(header.Key, "Date", StringComparison.OrdinalIgnoreCase))
            .Select(header => $"{header.Key}: {string.Join(',', header.Value)}")
            .Order(StringComparer.Ordinal);

        return new ObservedAnswer(
            route,
            method.Method,
            (int)response.StatusCode,
            string.Join('\n', headers),
            await response.Content.ReadAsStringAsync());
    }

    /// <summary>
    /// Determines whether the answer carries a header that would describe the deployment.
    /// </summary>
    /// <param name="header">The header to look for.</param>
    /// <returns><see langword="true"/> when the answer carries it; otherwise <see langword="false"/>.</returns>
    public bool Carries(string header) => Headers.Contains($"{header}:", StringComparison.OrdinalIgnoreCase);
}
