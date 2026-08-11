// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.Management;

namespace Cratis.AuthProxy.Security.for_ManagementListener;

/// <summary>
/// A private management listener is a second door into a reverse proxy, so what it is reachable from and
/// what it will do are the whole question.
/// <para>
/// The exchanges below are made against two real Kestrel sockets rather than an in-memory test server,
/// because the isolation is gated on the socket a request was accepted on. A test server has no socket and
/// reports the local port as zero, which would make every one of these assertions pass against an
/// implementation that mapped the endpoints globally and isolated nothing.
/// </para>
/// </summary>
/// <param name="harness">The two running proxies and their shared origin.</param>
[Collection(given.ManagementListenerSpecCollection.Name)]
public class when_a_management_listener_is_open(ManagementListenerHarness harness) : IAsyncLifetime
{
    readonly Dictionary<string, Answer> _answers = [];
    int _outboundBeforeProbes;
    int _outboundAfterProbes;
    bool _originSawManagementPortTraffic;

    public async Task InitializeAsync()
    {
        using var client = ManagementListenerHarness.CreateClient();

        // The public listener, doing exactly what it did before any of this existed.
        await Capture(client, "public-anonymous", $"{harness.PublicBaseUrl}{ManagementListenerHarness.AnonymousPath}");

        // The management paths, offered to the internet-facing listener — with and without a Host header
        // claiming to be the management listener.
        await Capture(client, "public-live", $"{harness.PublicBaseUrl}/health/live");
        await Capture(client, "public-ready", $"{harness.PublicBaseUrl}/health/ready");
        await Capture(client, "public-live-forged-host", $"{harness.PublicBaseUrl}/health/live", $"proxy.example.com:{harness.ManagementPort}");
        await Capture(client, "public-anonymous-forged-host", $"{harness.PublicBaseUrl}{ManagementListenerHarness.AnonymousPath}", $"proxy.example.com:{harness.ManagementPort}");

        // The probes themselves, with the origin cleared and the outbound client count read either side, so
        // "they call nothing" is asserted rather than assumed.
        harness.Origin.Clear();
        _outboundBeforeProbes = harness.OutboundClientsCreated;
        await Capture(client, "management-live", $"{harness.ManagementBaseUrl}/health/live");
        await Capture(client, "management-ready", $"{harness.ManagementBaseUrl}/health/ready");
        _outboundAfterProbes = harness.OutboundClientsCreated;

        // Everything the deployment actually serves, offered to the private listener.
        await Capture(client, "management-root", $"{harness.ManagementBaseUrl}/");
        await Capture(client, "management-api", $"{harness.ManagementBaseUrl}/api/x");
        await Capture(client, "management-providers", $"{harness.ManagementBaseUrl}{WellKnownPaths.Providers}");
        await Capture(client, "management-anonymous", $"{harness.ManagementBaseUrl}{ManagementListenerHarness.AnonymousPath}");
        await Capture(client, "management-asset", $"{harness.ManagementBaseUrl}/index.html");
        await Capture(client, "management-unknown", $"{harness.ManagementBaseUrl}/anything-at-all");

        _originSawManagementPortTraffic = !harness.Origin.Received.IsEmpty;

        // Sent after the record was read, so that what the origin saw for these is unambiguously the result
        // of a request on the public listener rather than something left over from an earlier one.
        await Capture(client, "public-anonymous-again", $"{harness.PublicBaseUrl}{ManagementListenerHarness.AnonymousPath}");
        await Capture(client, "public-application-health", $"{harness.PublicBaseUrl}{ManagementListenerHarness.ApplicationHealthPath}");
        await Capture(client, "public-application-health-child", $"{harness.PublicBaseUrl}{ManagementListenerHarness.ApplicationHealthPath}/status");
    }

    public Task DisposeAsync() => Task.CompletedTask;

    [Fact]
    public void should_bind_both_listeners() =>
        Assert.Equal(2, harness.ConfiguredAddresses.Count);

    [Fact]
    public void should_bind_the_management_listener_on_the_declared_port() =>
        Assert.Contains(harness.ConfiguredAddresses, address => ListenerAddresses.PortOf(address) == harness.ManagementPort);

    [Fact]
    public void should_open_no_second_socket_for_a_deployment_that_never_asked() =>
        Assert.Single(harness.BareAddresses);

    [Fact]
    public void should_serve_the_public_listener_while_the_management_listener_is_open() =>
        Assert.Equal(HttpStatusCode.OK, StatusOf("public-anonymous"));

    [Fact]
    public void should_still_serve_the_public_listener_after_the_management_listener_answered() =>
        Assert.Equal(HttpStatusCode.OK, StatusOf("public-anonymous-again"));

    [Fact]
    public void should_answer_liveness_on_the_management_listener() =>
        Assert.Equal(HttpStatusCode.OK, StatusOf("management-live"));

    [Fact]
    public void should_answer_readiness_on_the_management_listener() =>
        Assert.Equal(HttpStatusCode.OK, StatusOf("management-ready"));

    [Fact]
    public void should_refuse_the_liveness_path_on_the_public_listener() =>
        Assert.Equal(HttpStatusCode.NotFound, StatusOf("public-live"));

    [Fact]
    public void should_refuse_the_readiness_path_on_the_public_listener() =>
        Assert.Equal(HttpStatusCode.NotFound, StatusOf("public-ready"));

    [Fact]
    public void should_still_refuse_a_management_path_carrying_a_forged_host_header() =>
        Assert.Equal(HttpStatusCode.NotFound, StatusOf("public-live-forged-host"));

    [Fact]
    public void should_not_restrict_an_ordinary_request_carrying_a_forged_host_header() =>
        Assert.Equal(HttpStatusCode.OK, StatusOf("public-anonymous-forged-host"));

    [Fact]
    public void should_refuse_the_root_on_the_management_listener() =>
        Assert.Equal(HttpStatusCode.NotFound, StatusOf("management-root"));

    [Fact]
    public void should_refuse_an_api_path_on_the_management_listener() =>
        Assert.Equal(HttpStatusCode.NotFound, StatusOf("management-api"));

    [Fact]
    public void should_refuse_the_providers_endpoint_on_the_management_listener() =>
        Assert.Equal(HttpStatusCode.NotFound, StatusOf("management-providers"));

    [Fact]
    public void should_refuse_a_declared_anonymous_path_on_the_management_listener() =>
        Assert.Equal(HttpStatusCode.NotFound, StatusOf("management-anonymous"));

    [Fact]
    public void should_refuse_a_bundled_asset_on_the_management_listener() =>
        Assert.Equal(HttpStatusCode.NotFound, StatusOf("management-asset"));

    [Fact]
    public void should_refuse_an_unknown_path_on_the_management_listener() =>
        Assert.Equal(HttpStatusCode.NotFound, StatusOf("management-unknown"));

    [Fact]
    public void should_forward_nothing_that_arrived_on_the_management_listener() =>
        Assert.False(_originSawManagementPortTraffic);

    [Fact]
    public void should_keep_serving_an_application_path_under_the_same_prefix() =>
        Assert.Equal(HttpStatusCode.OK, StatusOf("public-application-health"));

    [Fact]
    public void should_keep_serving_a_child_of_an_application_path_under_the_same_prefix() =>
        Assert.Equal(HttpStatusCode.OK, StatusOf("public-application-health-child"));

    [Fact]
    public void should_have_proxied_the_application_health_path_to_the_backend() =>
        Assert.True(harness.Origin.ReceivedAnythingFor(ManagementListenerHarness.ApplicationHealthPath));

    [Fact]
    public void should_make_no_outbound_request_while_answering_the_probes() =>
        Assert.Equal(_outboundBeforeProbes, _outboundAfterProbes);

    [Fact]
    public void should_not_hand_out_a_session_on_a_management_answer() =>
        Assert.DoesNotContain(ManagementAnswers, answer => answer.Headers.Contains("Set-Cookie"));

    [Fact]
    public void should_not_challenge_on_a_management_answer() =>
        Assert.DoesNotContain(ManagementAnswers, answer => answer.Headers.Contains("WWW-Authenticate"));

    [Fact]
    public void should_not_name_its_server_on_a_management_answer() =>
        Assert.DoesNotContain(ManagementAnswers, answer => answer.Headers.Contains("Server"));

    [Fact]
    public void should_not_name_the_product_on_a_management_answer() =>
        Assert.DoesNotContain(ManagementAnswers, answer => answer.Headers.Contains("AuthProxy", StringComparison.OrdinalIgnoreCase));

    [Fact]
    public void should_answer_a_bounded_body_on_the_management_listener() =>
        Assert.All(ManagementAnswers, answer => Assert.True(answer.Body.Length <= 32));

    [Fact]
    public void should_disclose_nothing_about_the_deployment_on_the_management_listener() =>
        Assert.DoesNotContain(harness.Origin.BaseUrl, string.Join('\n', ManagementAnswers.Select(answer => answer.Body)), StringComparison.Ordinal);

    [Fact]
    public void should_answer_the_same_refusal_from_either_listener() =>
        Assert.Equal(BodyOf("public-live"), BodyOf("management-unknown"));

    IEnumerable<Answer> ManagementAnswers =>
        _answers.Where(entry => entry.Key.StartsWith("management-", StringComparison.Ordinal)).Select(entry => entry.Value);

    HttpStatusCode StatusOf(string label) => _answers[label].Status;

    string BodyOf(string label) => _answers[label].Body;

    async Task Capture(HttpClient client, string label, string url, string? host = null)
    {
        using var request = new HttpRequestMessage(HttpMethod.Get, url);
        if (host is not null)
        {
            request.Headers.TryAddWithoutValidation("Host", host);
        }

        using var response = await client.SendAsync(request);
        _answers[label] = new Answer(
            response.StatusCode,
            await response.Content.ReadAsStringAsync(),
            string.Join('\n', response.Headers.Concat(response.Content.Headers).Select(header => $"{header.Key}: {string.Join(", ", header.Value)}")));
    }

    /// <summary>
    /// Represents one answer a listener gave, kept so every spec reads the same recorded exchange.
    /// </summary>
    /// <param name="Status">The status code the listener answered with.</param>
    /// <param name="Body">The response body, as a caller would read it.</param>
    /// <param name="Headers">Every response header, flattened so a spec can look for one by name.</param>
    sealed record Answer(HttpStatusCode Status, string Body, string Headers);
}
