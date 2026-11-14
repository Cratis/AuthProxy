// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Net;
using Cratis.AuthProxy.BearerRoutes;
using Cratis.AuthProxy.BearerRoutes.Introspection;
using Microsoft.Extensions.Logging.Abstractions;

namespace Cratis.AuthProxy.ForwardedIdentity.for_V2;

public class when_retaining_oauth_introspection_evidence : Specification
{
    const string CredentialId = "22222222-2222-4222-8222-222222222222";

    [Fact]
    public async Task should_cache_the_original_credential_and_expiration_without_extending_either()
    {
        var clock = new Clock();
        using var endpoint = new Endpoint(Answer("\"cache_epoch\":7,\"exp\":1700000010"));
        var introspector = Create(endpoint, clock);
        var issuer = Issuer();
        var validated = Validated(issuer);
        var first = await introspector.IntrospectWithEvidence("token", validated, issuer, CancellationToken.None);
        Assert.Equal(new IntrospectionCredential(CredentialId, "7"), first.Credential);
        Assert.Equal(clock.GetUtcNow().AddSeconds(10), first.ExpiresAt);
        clock.Advance(TimeSpan.FromSeconds(9));
        Assert.Equal(first, await introspector.IntrospectWithEvidence("token", validated, issuer, CancellationToken.None));
        Assert.Equal(1, endpoint.Requests);
        clock.Advance(TimeSpan.FromSeconds(1));
        endpoint.Body = Answer("\"cache_epoch\":8,\"exp\":1700000100");
        var fresh = await introspector.IntrospectWithEvidence("token", validated, issuer, CancellationToken.None);
        Assert.Equal("8", fresh.Credential!.Epoch);
        Assert.Equal(clock.GetUtcNow().AddSeconds(30), fresh.ValidUntil);
        Assert.Equal(2, endpoint.Requests);
    }

    [Theory]
    [InlineData("{\"active\":true,\"jti\":\"never-a-credential\"}")]
    [InlineData("{\"active\":true,\"cid\":\"22222222-2222-4222-8222-222222222222\"}")]
    [InlineData("{\"active\":true,\"credential_kind\":\"oauth-grant\",\"credential_id\":\"\"}")]
    [InlineData("{\"active\":true,\"credential_kind\":\"oauth-grant\",\"credential_id\":42}")]
    [InlineData("{\"active\":true,\"credential_kind\":\"oauth-grant\",\"credential_id\":\"not-a-uuid\"}")]
    [InlineData("{\"active\":true,\"credential_kind\":\"oauth-grant\",\"credential_id\":\"ABCDEFAB-1111-4111-8111-111111111111\"}")]
    [InlineData("{\"active\":true,\"credential_kind\":\"pat\",\"credential_id\":\"22222222-2222-4222-8222-222222222222\"}")]
    [InlineData("{\"active\":true,\"credential_id\":\"22222222-2222-4222-8222-222222222222\"}")]
    public async Task should_preserve_legacy_activity_but_not_invent_grant_evidence(string body)
    {
        using var endpoint = new Endpoint(body);
        var issuer = Issuer();
        var result = await Create(endpoint, new Clock()).IntrospectWithEvidence("token", Validated(issuer), issuer, CancellationToken.None);
        Assert.Equal(IntrospectionVerdict.Active, result.Verdict);
        Assert.Null(result.Credential);
    }

    [Theory]
    [InlineData("\"cnf\":{}", IntrospectionVerdict.Inactive)]
    [InlineData("\"cnf\":{\"jkt\":\"binding\"}", IntrospectionVerdict.Inactive)]
    [InlineData("\"credential_id\":\"22222222-2222-4222-8222-222222222222\"", IntrospectionVerdict.Active)]
    [InlineData("\"exp\":\"not-a-date\"", IntrospectionVerdict.Active)]
    public async Task should_not_return_grant_evidence_from_ambiguous_or_bound_answers(string extra, IntrospectionVerdict expected)
    {
        using var endpoint = new Endpoint(Answer(extra));
        var issuer = Issuer();
        var result = await Create(endpoint, new Clock()).IntrospectWithEvidence("token", Validated(issuer), issuer, CancellationToken.None);
        Assert.Equal(expected, result.Verdict);
        Assert.Null(result.Credential);
    }

    [Theory]
    [InlineData("{\"active\":false}", IntrospectionVerdict.Inactive)]
    [InlineData("{\"active\":true,\"sub\":\"another-person\"}", IntrospectionVerdict.Inactive)]
    [InlineData("not-json", IntrospectionVerdict.Unavailable)]
    public async Task should_never_cache_failed_or_contradictory_answers(string body, IntrospectionVerdict expected)
    {
        using var endpoint = new Endpoint(body);
        var issuer = Issuer();
        var introspector = Create(endpoint, new Clock());
        var validated = Validated(issuer);
        var first = await introspector.IntrospectWithEvidence("token", validated, issuer, CancellationToken.None);
        Assert.Equal(expected, first.Verdict);
        Assert.Null(first.Credential);
        await introspector.IntrospectWithEvidence("token", validated, issuer, CancellationToken.None);
        Assert.Equal(2, endpoint.Requests);
    }

    static string Answer(string extra) => $"{{\"active\":true,\"credential_kind\":\"oauth-grant\",\"credential_id\":\"{CredentialId}\",{extra}}}";

    static BearerTokenIntrospector Create(Endpoint endpoint, TimeProvider clock)
    {
        var factory = Substitute.For<IHttpClientFactory>();
        factory.CreateClient(Arg.Any<string>()).Returns(_ => new HttpClient(endpoint, disposeHandler: false));
        return new(factory, new IntrospectionCache(clock), clock, NullLogger<BearerTokenIntrospector>.Instance);
    }

    static ResolvedBearerIssuer Issuer() => new("https://realm.example", "https://realm.example/metadata", ["at+jwt"], true)
    {
        Introspection = new() { Endpoint = "https://realm.example/introspect", ClientId = "client", ClientSecret = "synthetic-test-only" }
    };

    static BearerTokenValidation Validated(ResolvedBearerIssuer issuer)
    {
        var identity = new ClaimsIdentity([new Claim(BearerRouteClaims.Subject, "person"), new Claim("scope", "read"), new Claim("exp", "1700000100")], "Bearer");
        return BearerTokenValidation.Success(new ClaimsPrincipal(identity), "tenant") with { Issuer = issuer };
    }

    sealed class Clock : TimeProvider
    {
        DateTimeOffset _now = DateTimeOffset.FromUnixTimeSeconds(1_700_000_000);
        public override DateTimeOffset GetUtcNow() => _now;
        internal void Advance(TimeSpan duration) => _now += duration;
    }

    sealed class Endpoint(string body) : HttpMessageHandler
    {
        internal int Requests { get; private set; }
        internal string Body { get; set; } = body;
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            Requests++;
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent(Body) });
        }
    }
}
