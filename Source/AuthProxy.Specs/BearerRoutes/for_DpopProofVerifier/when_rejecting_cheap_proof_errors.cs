// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.BearerRoutes.for_DpopProofVerifier;

public class when_rejecting_cheap_proof_errors : given_a_dpop_gate
{
    [Theory]
    [InlineData("missing")]
    [InlineData("empty")]
    [InlineData("oversized")]
    [InlineData("malformed")]
    [InlineData("multiple")]
    public async Task should_never_call_the_store_for_structural_errors(string error)
    {
        var context = Request(error == "oversized" ? new string('A', 4097) : "not.a.proof");
        if (error == "missing") context.Request.Headers.Remove("DPoP");
        if (error == "empty") context.Request.Headers["DPoP"] = string.Empty;
        if (error == "multiple") context.Request.Headers["DPoP"] = new[] { Proof(), Proof() };
        Options.Dpop.NonceRequired = true;
        await Gate.InvokeAsync(context);
        Refused(context, 401);
        Store.HealthChecks.ShouldEqual(0);
        Store.Consumes.ShouldEqual(0);
        context.Response.Headers.ContainsKey("DPoP-Nonce").ShouldBeFalse();
    }
}
