// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.Identity;

namespace Cratis.AuthProxy.Security.for_BearerIntrospection;

/// <summary>
/// Introspection can only narrow who gets through. Whatever else the endpoint says — more scopes, another tenant,
/// another subject's roles — the forwarded identity is exactly what the validated token carries, and an answer that
/// contradicts the token is refused rather than believed.
/// </summary>
/// <param name="harness">The running proxy, origin, issuer and introspection endpoint.</param>
[Collection(IntrospectionSpecCollection.Name)]
public class when_introspection_reports_more_than_the_token(IntrospectionHarness harness) : IAsyncLifetime
{
    const string Path = $"{IntrospectionHarness.MarkedRoute}/tools";

    ForwardedRequest? _forwarded;
    ClientPrincipal? _principal;
    HttpStatusCode _otherSubject;
    HttpStatusCode _otherClient;
    HttpStatusCode _minimal;

    public async ValueTask InitializeAsync()
    {
        using var client = harness.CreateBearerClient();
        harness.Endpoint.Reset();

        var token = harness.Issuer.Token();
        harness.Endpoint.Activate(token, "\"scope\":\"admin:all\",\"tid\":\"99999999-9999-9999-9999-999999999999\",\"aud\":\"another-api\",\"username\":\"mallory\",\"roles\":[\"admin\"],\"exp\":4102444800");
        harness.Origin.Clear();
        using var response = await client.SendAsync(BearerRouteHarness.WithToken(HttpMethod.Get, Path, token));
        _forwarded = harness.Origin.LastRequestTo(Path);
        ClientPrincipal.TryFromBase64(_forwarded?.Value(Headers.Principal), out _principal);

        var other = harness.Issuer.Token();
        harness.Endpoint.Activate(other, "\"sub\":\"someone-else\"");
        _otherSubject = (await Send(client, other)).StatusCode;

        var another = harness.Issuer.Token();
        harness.Endpoint.Activate(another, "\"client_id\":\"another-client\"");
        _otherClient = (await Send(client, another)).StatusCode;

        var bare = harness.Issuer.Token();
        harness.Endpoint.Activate(bare);
        _minimal = (await Send(client, bare)).StatusCode;
    }

    public ValueTask DisposeAsync() => ValueTask.CompletedTask;

    [Fact] public void should_forward_the_request() => Assert.NotNull(_forwarded);
    [Fact] public void should_forward_the_tenant_of_the_token() => Assert.Equal(BearerRouteHarness.TenantId, _forwarded!.Value(Headers.TenantId));
    [Fact] public void should_forward_the_scopes_of_the_token() => Assert.Equal("direct:read direct:work", _forwarded!.Value(Headers.TokenScope));
    [Fact] public void should_forward_the_principal_of_the_token() => Assert.Equal(BearerRouteHarness.GitHubLogin, _forwarded!.Value(Headers.PrincipalName));
    [Fact] public void should_carry_nothing_the_endpoint_said_into_the_principal() => Assert.DoesNotContain(_principal!.Claims, _ => new[] { "mallory", "admin", "admin:all" }.Contains(_.Value, StringComparer.Ordinal));
    [Fact] public void should_refuse_an_answer_for_another_subject() => Assert.Equal(HttpStatusCode.Unauthorized, _otherSubject);
    [Fact] public void should_refuse_an_answer_for_another_client() => Assert.Equal(HttpStatusCode.Unauthorized, _otherClient);
    [Fact] public void should_accept_an_answer_that_only_says_active() => Assert.Equal(HttpStatusCode.OK, _minimal);

    static async Task<HttpResponseMessage> Send(HttpClient client, string token) =>
        await client.SendAsync(BearerRouteHarness.WithToken(HttpMethod.Get, Path, token));
}
