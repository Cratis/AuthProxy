// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.Authorization;

namespace Cratis.AuthProxy.BearerRoutes.for_DpopProofVerifier;

public class when_refusing_proof_before_authorization : given_a_dpop_gate
{
    [Theory]
    [InlineData(false, false)]
    [InlineData(true, false)]
    [InlineData(false, true)]
    [InlineData(true, true)]
    public async Task should_return_401_without_consulting_policy_or_tenants(bool missing, bool denyPolicy)
    {
        Options.TenantVerification = new() { UrlTemplate = "https://tenants.example.test/{tenantId}" };
        if (denyPolicy) Access.Evaluate(Arg.Any<ClaimsPrincipal>(), Arg.Any<C.AuthProxy>(), Arg.Any<string>(), Arg.Any<C.BearerRoute>()).Returns(AccessDecision.Denied("role"));
        Tenants.VerifyAsync(Arg.Any<string>()).Returns(false);
        var context = Request("malformed");
        if (missing) context.Request.Headers.Remove("DPoP");
        await Gate.InvokeAsync(context);
        Refused(context, 401);
        Access.ReceivedCalls().ShouldBeEmpty();
        Tenants.ReceivedCalls().ShouldBeEmpty();
    }
}
