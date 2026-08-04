// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Net;
using System.Net.Http.Headers;

namespace Cratis.AuthProxy.Scenarios.when_multiple_providers_are_configured;

/// <summary>
/// End-to-end: the callers that are not browsers navigating to a document must be refused with
/// <c>401</c> rather than handed the provider-selection page at <c>200</c>.
/// <para>
/// Three shapes are exercised because each records the <c>200</c> as a success in its own way — a
/// <c>fetch()</c> from a frontend (<c>Sec-Fetch-Dest: empty</c>, <c>Accept: *&#47;*</c>), a webhook stating
/// only that it wants JSON, and a bare client stating nothing at all. The last is the one that matters
/// most for delivery: it is what most webhook senders and every <c>curl</c> look like, and it is the shape
/// a naive Accept-only rule would still answer with HTML.
/// </para>
/// <para>
/// <c>/.cratis/me</c> is requested by name because it is the concrete instance: Arc's
/// <c>IdentityProvider</c> calls it on boot, and the page arriving as <c>200 text/html</c> makes
/// <c>response.ok</c> true so only the following <c>.json()</c> fails.
/// </para>
/// </summary>
/// <param name="factory">The shared application factory.</param>
public class and_a_non_browser_caller_requests_a_page(AuthProxyFactory factory) : IClassFixture<AuthProxyFactory>, IAsyncLifetime
{
    HttpResponseMessage? _fetch;
    HttpResponseMessage? _webhook;
    HttpResponseMessage? _bareClient;
    HttpResponseMessage? _identityBootstrap;
    string? _identityBootstrapBody;

    public async Task InitializeAsync()
    {
        using var client = factory.CreateTestClient();

        _fetch = await client.SendAsync(Request("/api/orders", accept: "*/*", fetchDestination: "empty"));
        _webhook = await client.SendAsync(Request("/api/callbacks/esign", accept: "application/json"));
        _bareClient = await client.SendAsync(Request("/api/callbacks/esign"));

        _identityBootstrap = await client.SendAsync(Request(WellKnownPaths.IdentityDetails, accept: "*/*", fetchDestination: "empty"));
        _identityBootstrapBody = await _identityBootstrap.Content.ReadAsStringAsync();
    }

    public Task DisposeAsync() => Task.CompletedTask;

    static HttpRequestMessage Request(string path, string? accept = null, string? fetchDestination = null)
    {
        var request = new HttpRequestMessage(HttpMethod.Get, path);

        if (accept is not null)
        {
            request.Headers.Accept.Add(MediaTypeWithQualityHeaderValue.Parse(accept));
        }

        if (fetchDestination is not null)
        {
            request.Headers.Add("Sec-Fetch-Dest", fetchDestination);
        }

        return request;
    }

    [Fact] public void should_refuse_a_fetch_from_a_frontend() => Assert.Equal(HttpStatusCode.Unauthorized, _fetch!.StatusCode);
    [Fact] public void should_refuse_a_webhook_asking_for_json() => Assert.Equal(HttpStatusCode.Unauthorized, _webhook!.StatusCode);
    [Fact] public void should_refuse_a_client_stating_nothing() => Assert.Equal(HttpStatusCode.Unauthorized, _bareClient!.StatusCode);

    [Fact] public void should_refuse_the_identity_bootstrap() => Assert.Equal(HttpStatusCode.Unauthorized, _identityBootstrap!.StatusCode);
    [Fact] public void should_not_answer_the_identity_bootstrap_with_a_page() => Assert.DoesNotContain("Select Provider", _identityBootstrapBody);

    [Fact]
    public void should_not_set_the_providers_cookie_for_a_caller_that_gets_no_page() =>
        Assert.False(
            _fetch!.Headers.TryGetValues("Set-Cookie", out var cookies)
            && cookies.Any(_ => _.StartsWith(Cookies.Providers, StringComparison.OrdinalIgnoreCase)),
            "Expected no providers cookie when no selection page is served");
}
