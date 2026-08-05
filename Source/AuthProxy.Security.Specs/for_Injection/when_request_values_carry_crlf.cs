// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Security.for_Injection;

/// <summary>
/// OWASP A03 — Injection. A caller must not be able to write a header by putting a line break in a value.
/// <para>
/// CR/LF injection is header forgery through the back door. AuthProxy copies caller-supplied values into
/// two places where a line break would be catastrophic: the request it forwards to the origin, and the
/// <c>Location</c> it hands the browser. A newline surviving into the forwarded request means the attacker
/// is writing headers the backend trusts — the same identity forgery the proxy exists to prevent, only
/// smuggled inside a value nobody thought to sanitize. A newline surviving into a response splits the
/// response itself: the attacker appends headers, or a second body the browser accepts as a legitimate
/// answer from this origin, which is how cache poisoning and reflected scripting are staged against a
/// domain the victim already trusts.
/// </para>
/// <para>
/// The payloads travel in URLs rather than in headers, because a header attempt would test the client
/// instead of the proxy — <see cref="System.Net.Http.HttpClient"/> will not put a control character on the
/// wire. Both forms are sent, and both arrive: <see cref="Uri"/> percent-escapes the raw
/// <c>CR</c>/<c>LF</c> as it builds the request, so the raw and the pre-encoded payload reach AuthProxy as
/// the same bytes — and ASP.NET Core hands both back as genuine control characters once the query value is
/// decoded. Nothing is normalized away here; every payload reaches the code under test intact.
/// </para>
/// <para>
/// Three sinks are probed. The query string of a proxied request lands in the request the backend sees, so
/// that assertion is made against what the origin actually recorded rather than against the client-facing
/// response. The <c>returnUrl</c> of <c>/.cratis/login/{scheme}</c> is the value AuthProxy normalizes and
/// round-trips through the identity provider; the endpoint runs and consumes it, but this harness replaces
/// the authentication schemes to present a session as a header, which leaves the configured provider with
/// no handler to challenge with, so that probe cannot produce a redirect to read. The <c>redirect</c> of
/// <c>/.cratis/logout</c> is therefore probed as well — it is the sink in this harness that does reach a
/// real <c>Location</c> header, and without it the response-splitting assertions would pass by never
/// having a redirect to inspect.
/// </para>
/// <para>
/// That third probe is written to leave the redirect policy only one thing to object to. A payload that
/// does not begin with <c>/</c> is refused for not looking same-site at all, which would prove nothing
/// about line breaks, so the redirect variants keep a real same-site path in front and drop the space out
/// of the forged header. What remains that a policy could refuse is the <c>CR</c> and the <c>LF</c>. A
/// clean target is sent through the same endpoint as a control, so the payloads falling back to <c>/</c>
/// reads as a refusal rather than as an endpoint that ignores the parameter.
/// </para>
/// </summary>
/// <param name="harness">The running proxy and its origin.</param>
[Collection(SecuritySpecCollection.Name)]
public class when_request_values_carry_crlf(SecurityHarness harness) : IAsyncLifetime
{
    const string InjectedHeader = "X-Injected";
    const string LoginPath = $"{WellKnownPaths.LoginPrefix}/provider-one";
    const string LegitimateRedirect = "/dashboard";

    /// <summary>
    /// The forged header in raw and percent-encoded form, each paired with the variant used against a
    /// redirect target — same-site prefix kept and the space dropped, so the only thing a redirect policy
    /// can object to is the line break itself.
    /// </summary>
    static readonly (string Value, string Redirect)[] _payloads =
    [
        ("\r\nX-Injected: yes", $"{LegitimateRedirect}\r\nX-Injected:yes"),
        ("%0d%0aX-Injected:%20yes", $"{LegitimateRedirect}%0d%0aX-Injected:yes"),
    ];

    readonly List<Exchange> _exchanges = [];
    readonly List<Exchange> _logouts = [];
    readonly List<ForwardedRequest?> _forwarded = [];
    Exchange? _legitimateLogout;

    public async Task InitializeAsync()
    {
        using var client = harness.CreateSecurityClient();

        foreach (var (value, redirect) in _payloads)
        {
            harness.Origin.Clear();
            _exchanges.Add(await Send(client, SecurityHarness.Authenticated(HttpMethod.Get, $"{SecurityHarness.ProtectedPath}?next={value}")));
            _forwarded.Add(harness.Origin.LastRequestTo(SecurityHarness.ProtectedPath));

            harness.Origin.Clear();
            _exchanges.Add(await Send(client, SecurityHarness.Anonymous(HttpMethod.Get, $"{LoginPath}?returnUrl={value}")));

            harness.Origin.Clear();
            var logout = await Send(client, SecurityHarness.Authenticated(HttpMethod.Get, $"{WellKnownPaths.Logout}?redirect={redirect}"));
            _logouts.Add(logout);
            _exchanges.Add(logout);
        }

        harness.Origin.Clear();
        _legitimateLogout = await Send(client, SecurityHarness.Authenticated(HttpMethod.Get, $"{WellKnownPaths.Logout}?redirect={LegitimateRedirect}"));
    }

    public Task DisposeAsync() => Task.CompletedTask;

    [Fact]
    public void should_still_honor_a_redirect_target_that_carries_no_line_break() =>
        Assert.Equal(LegitimateRedirect, _legitimateLogout!.Location);

    [Fact]
    public void should_have_delivered_the_payload_to_every_probed_sink() =>
        Assert.All(_exchanges, exchange => Assert.True(exchange.Reached || exchange.FailedOnlyAtSchemeDispatch));

    [Fact]
    public void should_have_forwarded_the_payload_to_the_origin() =>
        Assert.All(_forwarded, Assert.NotNull);

    [Fact]
    public void should_have_produced_a_redirect_to_inspect() =>
        Assert.All(_logouts, logout => Assert.NotEmpty(logout.Location));

    [Fact]
    public void should_fall_back_to_the_application_root_for_a_redirect_target_carrying_a_line_break() =>
        Assert.All(_logouts, logout => Assert.Equal("/", logout.Location));

    [Fact]
    public void should_never_write_the_injected_header_on_a_response() =>
        Assert.DoesNotContain(_exchanges, exchange => exchange.HeaderNames.Contains(InjectedHeader, StringComparer.OrdinalIgnoreCase));

    [Fact]
    public void should_never_carry_the_injected_header_to_the_origin() =>
        Assert.All(_forwarded, forwarded => Assert.False(forwarded!.Has(InjectedHeader)));

    [Fact]
    public void should_never_name_the_injected_header_in_what_the_origin_received() =>
        Assert.DoesNotContain(_forwarded, forwarded => forwarded!.Headers.Values.Any(value => value.Contains(InjectedHeader, StringComparison.OrdinalIgnoreCase)));

    [Fact]
    public void should_never_put_a_raw_carriage_return_in_a_redirect_target() =>
        Assert.All(_exchanges, exchange => Assert.DoesNotContain('\r', exchange.Location));

    [Fact]
    public void should_never_put_a_raw_line_feed_in_a_redirect_target() =>
        Assert.All(_exchanges, exchange => Assert.DoesNotContain('\n', exchange.Location));

    [Fact]
    public void should_never_put_a_raw_carriage_return_in_any_response_header() =>
        Assert.All(_exchanges, exchange => Assert.DoesNotContain('\r', exchange.HeaderValues));

    [Fact]
    public void should_never_put_a_raw_line_feed_in_any_response_header() =>
        Assert.All(_exchanges, exchange => Assert.DoesNotContain('\n', exchange.HeaderValues));

    static async Task<Exchange> Send(HttpClient client, HttpRequestMessage request)
    {
        try
        {
            using var response = await client.SendAsync(request);

            var headers = response.Headers.Concat(response.Content.Headers).ToArray();

            return new Exchange(
                true,
                string.Empty,
                [.. headers.Select(header => header.Key)],
                string.Concat(headers.SelectMany(header => header.Value)),
                string.Concat(response.Headers.TryGetValues("Location", out var location) ? location : []));
        }
        catch (Exception ex)
        {
            // The proxy never answered. What failed matters: a rejection the payload caused is a result,
            // while the harness being unable to dispatch a challenge is not, and the two must not be
            // allowed to look alike.
            return new Exchange(false, $"{ex.GetType().Name}: {ex.Message}", [], string.Empty, string.Empty);
        }
    }

    /// <summary>
    /// Records what one payload produced on the client-facing response.
    /// </summary>
    /// <param name="Reached">Whether the proxy answered at all.</param>
    /// <param name="Failure">The failure that replaced an answer, or an empty string when there was one.</param>
    /// <param name="HeaderNames">Every response header name.</param>
    /// <param name="HeaderValues">Every response header value, concatenated.</param>
    /// <param name="Location">The raw <c>Location</c> header, or an empty string when there was none.</param>
    sealed record Exchange(bool Reached, string Failure, IReadOnlyCollection<string> HeaderNames, string HeaderValues, string Location)
    {
        /// <summary>
        /// Gets whether the only thing that stopped this exchange was the harness having no handler
        /// registered for the configured provider scheme.
        /// </summary>
        /// <remarks>
        /// The harness replaces the authentication schemes so a spec can present a session as a header, and
        /// that leaves the configured OIDC provider without a handler to challenge with. The endpoint still
        /// runs — it parses and normalizes the caller's <c>returnUrl</c> before it ever asks for a
        /// challenge, so the payload does reach the code under test — but dispatch then fails and there is
        /// no response to read a header from. Recognizing that exact failure keeps it from silently
        /// standing in for a genuine refusal, and makes this spec fail the day the scheme becomes
        /// challengeable and a real <c>Location</c> needs asserting on.
        /// </remarks>
        public bool FailedOnlyAtSchemeDispatch =>
            Failure.Contains("No authentication handler is registered", StringComparison.Ordinal);
    }
}
