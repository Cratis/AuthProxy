// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Security.for_Injection;

/// <summary>
/// OWASP A03 — Injection. A caller must not be able to name a file outside the pages directory.
/// <para>
/// The <c>/_pages</c> branch is the one place AuthProxy reads the disk on behalf of an unauthenticated
/// caller, and by design it answers before authentication so a login or error page stays reachable without
/// a session. Anonymous, pre-auth and file-backed is the highest-value path-traversal combination the
/// component has: a deployment's configuration, its data-protection keys and its mounted secrets all live
/// near the directories this branch reads from, so a single escape turns the login page into an arbitrary
/// file read for anyone who can reach the host.
/// </para>
/// <para>
/// That risk is concrete rather than theoretical here, because the proxy's own <c>appsettings.json</c> sits
/// directly beside its <c>Pages</c> directory — one <c>../</c> is the entire distance between serving a
/// login page and serving the deployment's configuration. So the payloads walk the evasion ladder instead
/// of repeating one canonical <c>../</c>: percent-encoded dots, an encoded separator, doubled dots that
/// survive a naive strip, double encoding, Windows-style backslashes, and a rooted path.
/// </para>
/// <para>
/// The payloads do not all arrive intact, and the spec is written so that this is visible rather than
/// papered over. Two layers below AuthProxy defuse most of them, and neither is this component's code:
/// <see cref="Uri"/> collapses dot segments and rewrites backslashes as the request is built, so the three
/// plain <c>../</c> forms are already ordinary paths before the proxy sees them and are then refused by the
/// authentication gate; and the request path never decodes <c>%2f</c> into a separator, so the
/// encoded-separator forms arrive as one long literal file name inside the pages directory rather than as a
/// walk out of it. What is left reaches the pages handler and is refused there for want of a file.
/// </para>
/// <para>
/// That ordering is worth stating plainly, because it means the explicit containment check in
/// <c>ResolvePageAssetPath</c> — resolving the full path and requiring it to stay under the directory — is
/// never the thing that says no in these runs. It is the backstop for the day a layer above stops
/// normalizing, which is exactly how traversal bugs have historically appeared. So the assertions are made
/// on the outcome (nothing from outside the page directories is ever returned, and no payload comes back
/// with a body at all) rather than on the mechanism, and a status is demanded only of the payloads that
/// genuinely reached the handler.
/// </para>
/// <para>
/// A branch that answered 404 to everything would satisfy an outcome assertion while protecting nothing, so
/// three requests prove the surface is live alongside the attacks: <c>select-provider.html</c> from the
/// configured directory, <c>403.html</c> from the content-root directory that is the actual sibling of
/// <c>appsettings.json</c>, and the same file addressed with an encoded separator, which must fail — it is
/// what establishes that <c>%2f</c> is inert here and that the encoded-separator payloads were therefore
/// never a traversal in the first place.
/// </para>
/// </summary>
/// <param name="harness">The running proxy and its origin.</param>
[Collection(SecuritySpecCollection.Name)]
public class when_a_path_traverses_out_of_the_pages_root(SecurityHarness harness) : IAsyncLifetime
{
    const string ConfiguredPage = "/_pages/select-provider.html";
    const string ConfiguredPageContent = "Select Provider";
    const string ContentRootPage = "/_pages/403.html";
    const string EncodedSeparatorPage = "/_pages/sub%2f..%2f403.html";
    const string ConfigurationMarker = "AllowedHosts";
    const string PasswordFileMarker = "root:";

    static readonly string[] _payloads =
    [
        "/_pages/../appsettings.json",
        "/_pages/%2e%2e/appsettings.json",
        "/_pages/..%2f..%2fappsettings.json",
        "/_pages/..%2fappsettings.json",
        "/_pages/....//appsettings.json",
        "/_pages/%252e%252e/appsettings.json",
        "/_pages/..\\..\\appsettings.json",
        "/_pages/....\\\\/appsettings.json",
        "/_pages//etc/passwd",
    ];

    readonly List<Attempt> _attempts = [];
    Attempt? _configuredPage;
    Attempt? _contentRootPage;
    Attempt? _encodedSeparator;

    public async Task InitializeAsync()
    {
        using var client = harness.CreateSecurityClient();

        harness.Origin.Clear();

        foreach (var payload in _payloads)
        {
            _attempts.Add(await Request(client, payload));
        }

        _configuredPage = await Request(client, ConfiguredPage);
        _contentRootPage = await Request(client, ContentRootPage);
        _encodedSeparator = await Request(client, EncodedSeparatorPage);
    }

    public Task DisposeAsync() => Task.CompletedTask;

    [Fact]
    public void should_still_serve_a_page_from_the_configured_directory() =>
        Assert.Equal(HttpStatusCode.OK, _configuredPage!.Status);

    [Fact]
    public void should_serve_the_content_of_the_configured_page() =>
        Assert.Contains(ConfiguredPageContent, _configuredPage!.Body, StringComparison.Ordinal);

    [Fact]
    public void should_still_serve_a_page_from_the_directory_beside_the_configuration() =>
        Assert.Equal(HttpStatusCode.OK, _contentRootPage!.Status);

    [Fact]
    public void should_not_resolve_an_encoded_separator_as_a_path_separator() =>
        Assert.Equal(HttpStatusCode.NotFound, _encodedSeparator!.Status);

    [Fact]
    public void should_never_return_the_proxy_configuration() =>
        Assert.DoesNotContain(_attempts, attempt => attempt.Body.Contains(ConfigurationMarker, StringComparison.Ordinal));

    [Fact]
    public void should_never_return_an_operating_system_account_file() =>
        Assert.DoesNotContain(_attempts, attempt => attempt.Body.Contains(PasswordFileMarker, StringComparison.Ordinal));

    [Fact]
    public void should_never_answer_a_traversal_with_a_page_body() =>
        Assert.DoesNotContain(_attempts, attempt => attempt.Body.Contains(ConfiguredPageContent, StringComparison.Ordinal));

    [Fact]
    public void should_never_answer_a_traversal_with_any_content_at_all() =>
        Assert.All(_attempts, attempt => Assert.Empty(attempt.Body));

    [Fact]
    public void should_have_had_a_payload_reach_the_pages_handler() =>
        Assert.Contains(_attempts, attempt => attempt.ReachedPagesHandler);

    [Fact]
    public void should_have_had_a_payload_reach_the_pages_handler_aimed_at_the_configuration() =>
        Assert.Contains(
            _attempts,
            attempt => attempt.ReachedPagesHandler && attempt.Payload.Contains("..%2fappsettings.json", StringComparison.Ordinal));

    [Fact]
    public void should_refuse_every_payload_that_reaches_the_pages_handler() =>
        Assert.All(
            _attempts.Where(attempt => attempt.ReachedPagesHandler),
            attempt => Assert.Equal(HttpStatusCode.NotFound, attempt.Status));

    [Fact]
    public void should_refuse_every_payload_normalized_away_from_the_pages_handler() =>
        Assert.All(
            _attempts.Where(attempt => !attempt.ReachedPagesHandler),
            attempt => Assert.NotEqual(HttpStatusCode.OK, attempt.Status));

    static async Task<Attempt> Request(HttpClient client, string pathAndQuery)
    {
        using var request = SecurityHarness.Anonymous(HttpMethod.Get, pathAndQuery);
        using var response = await client.SendAsync(request);

        return new Attempt(
            pathAndQuery,
            response.RequestMessage?.RequestUri?.AbsolutePath ?? string.Empty,
            response.StatusCode,
            await response.Content.ReadAsStringAsync());
    }

    /// <summary>
    /// Records what one path produced, and whether it was still addressed at the pages branch by the time
    /// the proxy saw it.
    /// </summary>
    /// <param name="Payload">The path as the attacker wrote it.</param>
    /// <param name="EffectivePath">The path the request carried once <see cref="Uri"/> was done with it.</param>
    /// <param name="Status">The status the proxy answered with.</param>
    /// <param name="Body">The response body.</param>
    sealed record Attempt(string Payload, string EffectivePath, HttpStatusCode Status, string Body)
    {
        /// <summary>
        /// Gets whether the request still targeted the pages branch after client-side normalization, and
        /// therefore says something about AuthProxy rather than about <see cref="Uri"/>.
        /// </summary>
        public bool ReachedPagesHandler =>
            EffectivePath.StartsWith(WellKnownPaths.Pages, StringComparison.OrdinalIgnoreCase);
    }
}
