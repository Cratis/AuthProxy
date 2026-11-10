// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.BearerRoutes.for_DpopProofVerifier;

public class when_presenting_multiple_credentials : given_a_dpop_gate
{
    [Theory]
    [InlineData("headers")]
    [InlineData("folded")]
    [InlineData("query")]
    public async Task should_refuse_before_choosing_a_credential(string shape)
    {
        var context = Request();
        if (shape == "headers") context.Request.Headers.Authorization = new[] { "DPoP " + Token, "Bearer " + Token };
        if (shape == "folded") context.Request.Headers.Authorization = "DPoP " + Token + ", Bearer " + Token;
        if (shape == "query") context.Request.QueryString = new("?access_token=synthetic-other-token");
        await Gate.InvokeAsync(context);
        Refused(context, BearerChallenge.MultipleCredentialsStatusCode, "invalid_request");
        Validator.ReceivedCalls().ShouldBeEmpty();
        Store.HealthChecks.ShouldEqual(0);
        Store.Consumes.ShouldEqual(0);
    }
}
