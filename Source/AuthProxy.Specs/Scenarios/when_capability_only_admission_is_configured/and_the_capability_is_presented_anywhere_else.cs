// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Scenarios.when_capability_only_admission_is_configured;

/// <summary>
/// A capability presented anywhere other than the body of the admission endpoint admits nobody — even when
/// the value itself would have admitted.
/// <para>
/// The places refused here are the places a value gets written down without anyone deciding to write it
/// down: a path lands in access logs, proxy cache keys and browser history; a query string lands in
/// referrer headers; a header lands in tracing spans; a cookie is replayed by the browser to every
/// subsequent request. A capability is a bearer value, so accepting it from any of them would leak it by
/// routine operation rather than by attack.
/// </para>
/// </summary>
/// <param name="factory">The closed proxy under test.</param>
public class and_the_capability_is_presented_anywhere_else(AuthProxyFactory factory) : IClassFixture<AuthProxyFactory>, IAsyncLifetime
{
    readonly Dictionary<string, ObservedAnswer> _answers = new(StringComparer.Ordinal);
    readonly string _capability = AuthProxyFactory.MintCapability();

    string _presentingNothing = string.Empty;

    public async Task InitializeAsync()
    {
        using var client = factory.CreateProbingClient();

        _presentingNothing = (await ObservedAnswer.Capture(client, "/", HttpMethod.Get)).Shape;

        _answers["in the path"] = await ObservedAnswer.Capture(client, $"{AuthProxyFactory.AdmissionPath}/{_capability}", HttpMethod.Post);
        _answers["in the query string"] = await ObservedAnswer.Capture(client, $"{AuthProxyFactory.AdmissionPath}?capability={_capability}", HttpMethod.Post);
        _answers["in a header"] = await CaptureWithHeader(client, "X-Capability", _capability);
        _answers["in an authorization header"] = await CaptureWithHeader(client, "Authorization", $"Bearer {_capability}");
        _answers["in a cookie"] = await CaptureWithHeader(client, "Cookie", $"{Cookies.EntryTransaction}={_capability}");
    }

    public Task DisposeAsync() => Task.CompletedTask;

    [Fact]
    public void should_admit_nobody() =>
        Assert.Empty(_answers
            .Where(answer => !string.Equals(answer.Value.Shape, _presentingNothing, StringComparison.Ordinal))
            .Select(answer => answer.Key));

    [Fact]
    public void should_issue_no_cookie() =>
        Assert.Empty(_answers.Where(answer => answer.Value.Carries("Set-Cookie")).Select(answer => answer.Key));

    static async Task<ObservedAnswer> CaptureWithHeader(HttpClient client, string header, string value)
    {
        using var request = new HttpRequestMessage(HttpMethod.Post, AuthProxyFactory.AdmissionPath);
        request.Headers.TryAddWithoutValidation(header, value);

        using var response = await client.SendAsync(request);

        var headers = response.Headers
            .Concat(response.Content.Headers)
            .Where(entry => !string.Equals(entry.Key, "Date", StringComparison.OrdinalIgnoreCase))
            .Select(entry => $"{entry.Key}: {string.Join(',', entry.Value)}")
            .Order(StringComparer.Ordinal);

        return new ObservedAnswer(
            AuthProxyFactory.AdmissionPath,
            HttpMethod.Post.Method,
            (int)response.StatusCode,
            string.Join('\n', headers),
            await response.Content.ReadAsStringAsync());
    }
}
