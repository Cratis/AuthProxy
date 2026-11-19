// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.BearerRoutes.for_BearerTokenExchange.given;
using Cratis.AuthProxy.BearerRoutes.TokenExchange;

namespace Cratis.AuthProxy.BearerRoutes.for_BearerTokenExchange;

public class when_addressing_an_exchange
{
    [Fact]
    public async Task should_replace_the_header_before_normal_validation()
    {
        var request = new ExchangeRequest();
        (await request.Exchange.Prepare(request.Context, request.Resolved)).ShouldBeTrue();
        request.Context.Request.Headers.Authorization.ToString().ShouldEqual("Bearer " + ExchangeRequest.Jwt(request.Configuration.ResultIssuer));
        await request.Client.Received(1).Exchange(request.Configuration, request.Configuration.Issuers[0], Arg.Any<string>(), "tenant-a", Arg.Any<CancellationToken>());
    }

    [Theory]
    [InlineData(C.TenantSourceIdentifierResolverType.Default)]
    [InlineData(C.TenantSourceIdentifierResolverType.Selection)]
    [InlineData(C.TenantSourceIdentifierResolverType.Claim)]
    [InlineData(C.TenantSourceIdentifierResolverType.Specified)]
    public async Task should_not_use_an_ambient_tenant_as_the_target(C.TenantSourceIdentifierResolverType strategy)
    {
        var request = new ExchangeRequest();
        request.Targets(new TenantResolutionResult("tenant-a", strategy));
        (await request.Exchange.Prepare(request.Context, request.Resolved)).ShouldBeFalse();
        request.Context.Response.StatusCode.ShouldEqual(403);
        request.Client.ReceivedCalls().ShouldBeEmpty();
    }

    [Fact]
    public async Task should_refuse_without_an_addressed_target()
    {
        var request = new ExchangeRequest();
        request.Targets();
        (await request.Exchange.Prepare(request.Context, request.Resolved)).ShouldBeFalse();
        request.Client.ReceivedCalls().ShouldBeEmpty();
    }

    [Theory]
    [InlineData("tenant-b")]
    [InlineData("TENANT-A")]
    public async Task should_require_all_addressed_targets_to_agree_exactly(string other)
    {
        var request = new ExchangeRequest();
        request.Targets(new("tenant-a", C.TenantSourceIdentifierResolverType.Host), new(other, C.TenantSourceIdentifierResolverType.Route));
        (await request.Exchange.Prepare(request.Context, request.Resolved)).ShouldBeFalse();
        request.Client.ReceivedCalls().ShouldBeEmpty();
    }

    [Fact]
    public async Task should_ignore_a_spoofed_header_target()
    {
        var request = new ExchangeRequest();
        request.Context.Request.Headers["X-Cratis-Tenant-Id"] = "attacker";
        request.Targets(new("attacker", C.TenantSourceIdentifierResolverType.Claim), new("tenant-a", C.TenantSourceIdentifierResolverType.Host));
        (await request.Exchange.Prepare(request.Context, request.Resolved)).ShouldBeTrue();
        await request.Client.Received(1).Exchange(Arg.Any<C.BearerTokenExchange>(), Arg.Any<C.BearerTokenExchangeIssuer>(), Arg.Any<string>(), "tenant-a", Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task should_refuse_a_nonexistent_tenant_before_exchange()
    {
        var request = new ExchangeRequest();
        request.Verifier.VerifyAsync(Arg.Any<string>(), Arg.Any<string?>()).Returns(false);
        (await request.Exchange.Prepare(request.Context, request.Resolved)).ShouldBeFalse();
        request.Client.ReceivedCalls().ShouldBeEmpty();
    }

    [Fact]
    public async Task should_bypass_exchange_for_a_direct_identity_token()
    {
        var request = new ExchangeRequest();
        var header = "Bearer " + ExchangeRequest.Jwt(request.Configuration.ResultIssuer);
        request.Context.Request.Headers.Authorization = header;
        (await request.Exchange.Prepare(request.Context, request.Resolved)).ShouldBeTrue();
        request.Context.Request.Headers.Authorization.ToString().ShouldEqual(header);
        request.Client.ReceivedCalls().ShouldBeEmpty();
    }

    [Fact]
    public async Task should_bypass_exchange_when_it_is_not_configured()
    {
        var request = new ExchangeRequest();
        request.Route.TokenExchange = null;
        (await request.Exchange.Prepare(request.Context, request.Resolved)).ShouldBeTrue();
        request.Client.ReceivedCalls().ShouldBeEmpty();
    }

    [Theory]
    [InlineData(TokenExchangeVerdict.Refused, 401)]
    [InlineData(TokenExchangeVerdict.Unavailable, 401)]
    public async Task should_not_fall_back_after_exchange_failure(TokenExchangeVerdict verdict, int status)
    {
        var request = new ExchangeRequest();
        request.Client.Exchange(Arg.Any<C.BearerTokenExchange>(), Arg.Any<C.BearerTokenExchangeIssuer>(), Arg.Any<string>(), Arg.Any<string>(), Arg.Any<CancellationToken>()).Returns(new TokenExchangeResult(verdict, retryAfter: 4));
        (await request.Exchange.Prepare(request.Context, request.Resolved)).ShouldBeFalse();
        request.Context.Response.StatusCode.ShouldEqual(status);
        request.Context.Response.Headers.CacheControl.ToString().ShouldEqual("no-store");
        if (verdict == TokenExchangeVerdict.Unavailable) request.Context.Response.Headers.RetryAfter.ToString().ShouldEqual("4");
    }

    [Theory]
    [InlineData(BearerTokenValidationStatus.Invalid)]
    [InlineData(BearerTokenValidationStatus.IssuerUnavailable)]
    [InlineData(BearerTokenValidationStatus.MissingTenant)]
    public async Task should_normalize_failed_exchanged_token_validation_to_unauthorized(BearerTokenValidationStatus status)
    {
        var request = new ExchangeRequest();
        (await request.Exchange.Prepare(request.Context, request.Resolved)).ShouldBeTrue();
        var validation = BearerTokenValidation.Refused(status, "Refused.");
        request.Exchange.RefuseValidationFailure(request.Context, request.Resolved, validation).ShouldBeTrue();
        request.Context.Response.StatusCode.ShouldEqual(401);
    }

    [Fact]
    public void should_not_normalize_failed_validation_of_a_direct_identity_token()
    {
        var request = new ExchangeRequest();
        var validation = BearerTokenValidation.Refused(BearerTokenValidationStatus.IssuerUnavailable, "Unavailable.");
        request.Exchange.RefuseValidationFailure(request.Context, request.Resolved, validation).ShouldBeFalse();
    }

    [Theory]
    [InlineData("https://wrong.example", "direct-mcp", "tenant-a", "https://external.example")]
    [InlineData("https://identity.example", "https://cratis.direct/mcp", "tenant-a", "https://external.example")]
    [InlineData("https://identity.example", "direct-mcp", "tenant-b", "https://external.example")]
    [InlineData("https://identity.example", "direct-mcp", "TENANT-A", "https://external.example")]
    [InlineData("https://identity.example", "direct-mcp", "tenant-a", null)]
    [InlineData("https://identity.example", "direct-mcp", "tenant-a", "https://other.example")]
    public async Task should_refuse_the_wrong_returned_identity(string issuer, string audience, string tenant, string? idp)
    {
        var request = new ExchangeRequest();
        request.Client.Exchange(Arg.Any<C.BearerTokenExchange>(), Arg.Any<C.BearerTokenExchangeIssuer>(), Arg.Any<string>(), Arg.Any<string>(), Arg.Any<CancellationToken>())
            .Returns(new TokenExchangeResult(TokenExchangeVerdict.Success, ExchangeRequest.Jwt(issuer, audience, tenant, idp), 300));
        var prepared = await request.Exchange.Prepare(request.Context, request.Resolved);
        var accepted = prepared && request.Exchange.Confirm(request.Context, request.Resolved, request.Validation(tenant));
        accepted.ShouldBeFalse();
        var invalidToken = issuer != request.Configuration.ResultIssuer || audience != request.Configuration.Audience;
        request.Context.Response.StatusCode.ShouldEqual(invalidToken ? 401 : 403);
    }

    [Fact]
    public async Task should_not_trust_the_subject_tenants_or_subject_header()
    {
        var request = new ExchangeRequest();
        var subject = ExchangeRequest.Jwt(tenant: "attacker");
        request.Context.Request.Headers.Authorization = "Bearer " + subject;
        request.Context.Request.Headers["X-Cratis-Subject"] = "attacker";
        request.Context.Request.Headers["X-Cratis-Tenant-Id"] = "attacker";
        (await request.Exchange.Prepare(request.Context, request.Resolved)).ShouldBeTrue();
        await request.Client.Received(1).Exchange(request.Configuration, request.Configuration.Issuers[0], subject, "tenant-a", Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task should_not_cache_a_result_that_failed_postconditions()
    {
        var request = new ExchangeRequest();
        await request.Exchange.Prepare(request.Context, request.Resolved);
        request.Exchange.Confirm(request.Context, request.Resolved, request.Validation("other")).ShouldBeFalse();
        request.Context.Request.Headers.Authorization = "Bearer " + ExchangeRequest.Jwt();
        await request.Exchange.Prepare(request.Context, request.Resolved);
        await request.Client.Received(2).Exchange(Arg.Any<C.BearerTokenExchange>(), Arg.Any<C.BearerTokenExchangeIssuer>(), Arg.Any<string>(), Arg.Any<string>(), Arg.Any<CancellationToken>());
    }
}
