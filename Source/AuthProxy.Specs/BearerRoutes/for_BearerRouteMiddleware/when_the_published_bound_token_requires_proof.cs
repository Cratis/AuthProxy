// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Text.Json;
using Cratis.AuthProxy.Vectors;

namespace Cratis.AuthProxy.BearerRoutes.for_BearerRouteMiddleware;

public class when_the_published_bound_token_requires_proof : given_a_published_vector_gate
{
    [Theory]
    [InlineData(OAuthPath, false)]
    [InlineData(OAuthPath, true)]
    [InlineData(CombinedPath, false)]
    [InlineData(CombinedPath, true)]
    public async Task should_refuse_even_when_a_proof_header_is_present(string path, bool proofPresent)
    {
        var vector = PublishedAuthorizationVectors.Case("bound-token-requires-proof");
        var token = AccessToken(vector.GetProperty("given"));
        var context = Request(path, "GET", $"Bearer {token}");
        if (proofPresent) context.Request.Headers["DPoP"] = "synthetic-unsupported-proof";

        // Proof refusal precedes scope step-up, rather than suggesting reauthorization with broader scopes.
        Current.Services["api"].BearerRoutes.Single(_ => _.PathPrefix == path).RequiredScopes = ["direct:write"];

        await Middleware.InvokeAsync(context);

        AssertRefused(context, vector.GetProperty("then").GetProperty("status").GetInt32());
        Challenge(context).ShouldContain("error=\"invalid_token\"");
        Body(context).ShouldEqual(ErrorBody("unauthorized"));
        Body(context).ShouldNotContain(token);
        Challenge(context).ShouldNotContain(token);
    }

    [Theory]
    [InlineData("null")]
    [InlineData("\"\"")]
    [InlineData("7")]
    [InlineData("[]")]
    [InlineData("{}")]
    public async Task should_refuse_a_jkt_member_regardless_of_its_value(string value)
    {
        using var given = JsonDocument.Parse("{\"cnf\":{\"jkt\":" + value + "}}");
        var context = Request(OAuthPath, "GET", $"Bearer {AccessToken(given.RootElement)}");

        await Middleware.InvokeAsync(context);

        AssertRefused(context, StatusCodes.Status401Unauthorized);
        Challenge(context).ShouldContain("error=\"invalid_token\"");
    }
}
