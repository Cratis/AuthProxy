// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.BearerRoutes.for_DpopProofVerifier;

public class when_proof_precedes_scope_step_up : given_a_dpop_gate
{
    void Establish()
    {
        Policy.RequiredScopes = ["direct:write"];
        Validation = Validation with { Status = BearerTokenValidationStatus.InsufficientScope };
    }

    [Fact]
    public async Task should_use_a_dpop_scope_challenge_only_after_a_valid_proof()
    {
        var request = Request();
        await Gate.InvokeAsync(request);
        Refused(request, 403, "insufficient_scope");
        request.Response.Headers.WWWAuthenticate.ToString().ShouldContain("DPoP");
        Store.Count.ShouldEqual(1);
    }

    [Fact]
    public async Task should_refuse_bad_proof_before_suggesting_broader_scope()
    {
        var before = Store.Count;
        var request = Request("invalid-proof");
        await Gate.InvokeAsync(request);
        Refused(request, 401);
        Store.Count.ShouldEqual(before);
    }
}
