// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Net;
using System.Text;
using Microsoft.Net.Http.Headers;

namespace Cratis.AuthProxy.Scenarios.when_capability_only_admission_is_configured;

/// <summary>
/// A capability the deployment's verifier admits opens the door, and opens it exactly as wide as it was
/// always open: the provider list answers, the challenge endpoint answers, the page assets and the bundled
/// web assets answer.
/// <para>
/// What goes into the browser is one cookie carrying the sealed record that a verifier said yes — never the
/// capability, and nothing derived from it. That is asserted against the raw bytes of the cookie rather
/// than against the record the code meant to store, because the bytes are what the browser, and every proxy
/// and log between here and it, actually receives.
/// </para>
/// </summary>
/// <param name="factory">The closed proxy under test.</param>
public class and_a_valid_capability_is_presented(AuthProxyFactory factory) : IClassFixture<AuthProxyFactory>, IAsyncLifetime
{
    readonly string _capability = AuthProxyFactory.MintCapability();

    HttpStatusCode _admissionStatus;
    string[] _issuedCookies = [];
    string _entryCookieValue = string.Empty;

    HttpResponseMessage? _providers;
    string _providersBody = string.Empty;
    HttpResponseMessage? _pageAsset;
    HttpResponseMessage? _webAsset;
    HttpResponseMessage? _unknownProvider;
    string _unknownProviderBody = string.Empty;

    public async Task InitializeAsync()
    {
        using var client = factory.CreateProbingClient();

        using var presentation = new HttpRequestMessage(HttpMethod.Post, AuthProxyFactory.AdmissionPath)
        {
            Content = new StringContent(_capability, Encoding.UTF8, "text/plain"),
        };
        using var admission = await client.SendAsync(presentation);

        _admissionStatus = admission.StatusCode;
        _issuedCookies = admission.Headers.TryGetValues("Set-Cookie", out var cookies) ? [.. cookies] : [];
        _entryCookieValue = SetCookieHeaderValue.Parse(_issuedCookies[0]).Value.ToString();

        _providers = await Admitted(client, WellKnownPaths.Providers);
        _providersBody = await _providers.Content.ReadAsStringAsync();
        _pageAsset = await Admitted(client, AuthProxyFactory.PageAssetPath);
        _webAsset = await Admitted(client, AuthProxyFactory.AssetPath);
        _unknownProvider = await Admitted(client, $"{WellKnownPaths.LoginPrefix}/no-such-provider");
        _unknownProviderBody = await _unknownProvider.Content.ReadAsStringAsync();
    }

    public Task DisposeAsync() => Task.CompletedTask;

    [Fact] public void should_admit_the_caller() => Assert.Equal(HttpStatusCode.NoContent, _admissionStatus);
    [Fact] public void should_issue_exactly_one_cookie() => Assert.Single(_issuedCookies);
    [Fact] public void should_issue_the_entry_transaction() => Assert.StartsWith($"{Cookies.EntryTransaction}=", _issuedCookies[0], StringComparison.Ordinal);
    [Fact] public void should_keep_the_cookie_away_from_script() => Assert.Contains("httponly", _issuedCookies[0], StringComparison.OrdinalIgnoreCase);
    [Fact] public void should_keep_the_cookie_on_same_site_navigation() => Assert.Contains("samesite=lax", _issuedCookies[0], StringComparison.OrdinalIgnoreCase);
    [Fact] public void should_scope_the_cookie_to_the_whole_host() => Assert.Contains("path=/", _issuedCookies[0], StringComparison.OrdinalIgnoreCase);

    [Fact]
    public void should_not_outlive_the_configured_entry_lifetime() =>
        Assert.True(SetCookieHeaderValue.Parse(_issuedCookies[0]).MaxAge <= TimeSpan.FromMinutes(10));

    [Fact]
    public void should_put_no_part_of_the_capability_in_the_cookie()
    {
        for (var start = 0; start + 6 <= _capability.Length; start++)
        {
            Assert.DoesNotContain(_capability.Substring(start, 6), _entryCookieValue, StringComparison.Ordinal);
        }
    }

    [Fact] public void should_answer_provider_discovery() => Assert.Equal(HttpStatusCode.OK, _providers!.StatusCode);
    [Fact] public void should_list_the_configured_providers() => Assert.Contains("Provider One", _providersBody, StringComparison.Ordinal);
    [Fact] public void should_serve_the_page_assets() => Assert.Equal(HttpStatusCode.OK, _pageAsset!.StatusCode);
    [Fact] public void should_serve_the_bundled_web_assets() => Assert.Equal(HttpStatusCode.OK, _webAsset!.StatusCode);

    [Fact]
    public void should_answer_the_challenge_endpoint_as_it_always_has() =>
        Assert.Contains("no-such-provider", _unknownProviderBody, StringComparison.Ordinal);

    async Task<HttpResponseMessage> Admitted(HttpClient client, string path)
    {
        using var request = new HttpRequestMessage(HttpMethod.Get, path);
        request.Headers.TryAddWithoutValidation("Cookie", $"{Cookies.EntryTransaction}={_entryCookieValue}");

        return await client.SendAsync(request);
    }
}
