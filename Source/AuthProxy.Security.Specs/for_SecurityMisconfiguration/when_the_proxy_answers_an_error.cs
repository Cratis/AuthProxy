// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Security.for_SecurityMisconfiguration;

/// <summary>
/// OWASP A05 — Security Misconfiguration. What a proxy says when it refuses is itself a disclosure.
/// <para>
/// An attacker's first move against an unfamiliar deployment is to make it fail, because a failing system
/// describes itself. A .NET stack trace names the exact types, methods and source files behind the door, so
/// the attacker stops guessing which product and version is running and starts reading its published
/// advisories. A configured backend address in a refusal body is worse: AuthProxy exists so that the origin
/// is only ever reachable through it, and naming that origin to a caller who was just refused hands over
/// the one thing they needed to try reaching it directly.
/// </para>
/// <para>
/// The most dangerous version of this is an error that fires <em>before</em> the request is authenticated.
/// Endpoint selection runs ahead of authentication, so a caller who can make route matching itself fail
/// gets that failure — and in a misconfigured environment its stack trace — without presenting a
/// credential. That is what a request satisfying two routes at once used to do here: sending both the
/// <c>Service-ID</c> header and the <c>?service=</c> query parameter matched two candidate routes with the
/// same template and the same order, which ASP.NET reports as an ambiguity and surfaces as a bare 500 to
/// anyone at all. Both shapes are exercised below, authenticated and not, so a reordering that reopens the
/// ambiguity is caught rather than shipped.
/// </para>
/// </summary>
/// <param name="harness">The running proxy and its origin.</param>
[Collection(SecuritySpecCollection.Name)]
public class when_the_proxy_answers_an_error(SecurityHarness harness) : IAsyncLifetime
{
    const string BothRoutesSameService = "/api/thing?service=app";
    const string BothRoutesCrossService = "/api/thing?service=other";

    readonly List<Answer> _answers = [];
    string _everyBody = string.Empty;

    public async Task InitializeAsync()
    {
        using var client = harness.CreateSecurityClient();

        // A refusal, plus every shape that satisfies both the header route and the query route at once.
        await Capture(client, "anonymous-protected", SecurityHarness.Anonymous(HttpMethod.Get, SecurityHarness.ProtectedPath));
        await Capture(client, "authenticated-same-service", ServiceHeader(SecurityHarness.Authenticated(HttpMethod.Get, BothRoutesSameService)));
        await Capture(client, "authenticated-cross-service", ServiceHeader(SecurityHarness.Authenticated(HttpMethod.Get, BothRoutesCrossService)));
        await Capture(client, "anonymous-same-service", ServiceHeader(SecurityHarness.Anonymous(HttpMethod.Get, BothRoutesSameService)));
        await Capture(client, "anonymous-cross-service", ServiceHeader(SecurityHarness.Anonymous(HttpMethod.Get, BothRoutesCrossService)));

        _everyBody = string.Join('\n', _answers.Select(answer => answer.Body));
    }

    public Task DisposeAsync() => Task.CompletedTask;

    [Fact]
    public void should_not_disclose_a_stack_frame_in_any_response() =>
        Assert.DoesNotContain("at Cratis.AuthProxy.", _everyBody, StringComparison.Ordinal);

    [Fact]
    public void should_not_disclose_an_exception_type_in_any_response() =>
        Assert.DoesNotContain("System.Exception", _everyBody, StringComparison.Ordinal);

    [Fact]
    public void should_not_disclose_a_stack_trace_in_any_response() =>
        Assert.DoesNotContain("StackTrace", _everyBody, StringComparison.Ordinal);

    [Fact]
    public void should_not_disclose_a_source_file_and_line_in_any_response() =>
        Assert.DoesNotContain(".cs:line ", _everyBody, StringComparison.Ordinal);

    [Fact]
    public void should_not_fail_an_authenticated_request_matching_the_header_and_query_routes() =>
        Assert.NotEqual(HttpStatusCode.InternalServerError, StatusOf("authenticated-same-service"));

    [Fact]
    public void should_not_fail_an_authenticated_request_naming_another_service_in_the_query() =>
        Assert.NotEqual(HttpStatusCode.InternalServerError, StatusOf("authenticated-cross-service"));

    [Fact]
    public void should_not_fail_an_unauthenticated_request_matching_the_header_and_query_routes() =>
        Assert.NotEqual(HttpStatusCode.InternalServerError, StatusOf("anonymous-same-service"));

    [Fact]
    public void should_not_fail_an_unauthenticated_request_naming_another_service_in_the_query() =>
        Assert.NotEqual(HttpStatusCode.InternalServerError, StatusOf("anonymous-cross-service"));

    [Fact]
    public void should_refuse_an_unauthenticated_request_for_a_protected_path() =>
        Assert.Equal(HttpStatusCode.Unauthorized, StatusOf("anonymous-protected"));

    [Fact]
    public void should_not_disclose_the_backend_origin_to_an_unauthenticated_caller() =>
        Assert.DoesNotContain("127.0.0.1", BodyOf("anonymous-protected"), StringComparison.Ordinal);

    static HttpRequestMessage ServiceHeader(HttpRequestMessage request)
    {
        request.Headers.TryAddWithoutValidation(Headers.ServiceId, "app");

        return request;
    }

    async Task Capture(HttpClient client, string label, HttpRequestMessage request)
    {
        harness.Origin.Clear();

        var response = await client.SendAsync(request);
        _answers.Add(new Answer(label, response.StatusCode, await response.Content.ReadAsStringAsync()));
    }

    Answer Answered(string label) => _answers.Single(answer => string.Equals(answer.Label, label, StringComparison.Ordinal));

    HttpStatusCode StatusOf(string label) => Answered(label).Status;

    string BodyOf(string label) => Answered(label).Body;

    /// <summary>
    /// Represents one answer the proxy gave, kept so every spec reads the same recorded exchange.
    /// </summary>
    /// <param name="Label">The name the spec refers to this exchange by.</param>
    /// <param name="Status">The status code the proxy answered with.</param>
    /// <param name="Body">The response body, as a caller would read it.</param>
    sealed record Answer(string Label, HttpStatusCode Status, string Body);
}
