// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.BearerRoutes.for_BearerTokenExchange.given;
using Cratis.AuthProxy.BearerRoutes.TokenExchange;

namespace Cratis.AuthProxy.BearerRoutes.for_BearerTokenExchange;

public class when_a_tenant_claim_is_configured
{
    [Theory]
    [InlineData(null, "tid")]
    [InlineData(" ", "tid")]
    [InlineData("custom_tenant", "custom_tenant")]
    [InlineData(" custom_tenant ", "custom_tenant")]
    public async Task should_use_the_same_claim_as_normal_validation(string? configured, string claim)
    {
        var request = Request(configured, claim);
        (await request.Exchange.Prepare(request.Context, request.Resolved)).ShouldBeTrue();
        request.Exchange.Confirm(request.Context, request.Resolved, request.Validation()).ShouldBeTrue();
    }

    [Theory]
    [InlineData(null)]
    [InlineData("custom_tenant")]
    public async Task should_refuse_tenant_id_without_the_configured_claim(string? configured)
    {
        var request = Request(configured, "tenant_id");
        (await request.Exchange.Prepare(request.Context, request.Resolved)).ShouldBeFalse();
        request.Context.Response.StatusCode.ShouldEqual(401);
    }

    [Fact]
    public async Task should_check_the_raw_configured_claim_after_validation()
    {
        var request = Request("custom_tenant", "custom_tenant", "tenant-b");
        (await request.Exchange.Prepare(request.Context, request.Resolved)).ShouldBeTrue();
        request.Exchange.Confirm(request.Context, request.Resolved, request.Validation()).ShouldBeFalse();
        request.Context.Response.StatusCode.ShouldEqual(403);
    }

    static ExchangeRequest Request(string? configured, string claim, string tenant = "tenant-a")
    {
        var request = new ExchangeRequest();
        request.Route.TenantClaimType = configured!;
        var token = ExchangeRequest.Jwt(new Dictionary<string, object?>
        {
            ["iss"] = request.Configuration.ResultIssuer,
            ["aud"] = request.Configuration.Audience,
            ["exp"] = DateTimeOffset.UtcNow.AddMinutes(5).ToUnixTimeSeconds(),
            ["idp"] = request.Configuration.Issuers[0].Issuer,
            [claim] = tenant,
        });
        request.Client.Exchange(Arg.Any<C.BearerTokenExchange>(), Arg.Any<C.BearerTokenExchangeIssuer>(), Arg.Any<string>(), Arg.Any<string>(), Arg.Any<CancellationToken>())
            .Returns(new TokenExchangeResult(TokenExchangeVerdict.Success, token, 300));
        return request;
    }
}
