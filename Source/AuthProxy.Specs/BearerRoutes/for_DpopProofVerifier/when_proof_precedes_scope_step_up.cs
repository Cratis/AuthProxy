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
        var checks = Store.HealthChecks;
        var request = Request();
        await Gate.InvokeAsync(request);
        Refused(request, 403, "insufficient_scope");
        request.Response.Headers.WWWAuthenticate.ToString().ShouldContain("DPoP");
        Store.HealthChecks.ShouldEqual(checks + 1);
        Store.Consumes.ShouldEqual(0);
        Store.Count.ShouldEqual(0);
    }

    [Fact]
    public async Task should_require_a_ready_store_before_suggesting_broader_scope()
    {
        Store.Available = false;
        var request = Request();
        await Gate.InvokeAsync(request);
        Refused(request, 401);
        Store.Consumes.ShouldEqual(0);
        Store.Available = true;
    }

    [Fact]
    public async Task should_require_a_nonce_before_suggesting_broader_scope()
    {
        Options.Dpop.NonceRequired = true;
        var request = Request();
        await Gate.InvokeAsync(request);
        Refused(request, 401, "use_dpop_nonce");
        Payload["nonce"] = request.Response.Headers["DPoP-Nonce"].ToString();
        var retry = Request();
        await Gate.InvokeAsync(retry);
        Refused(retry, 403, "insufficient_scope");
        Store.Consumes.ShouldEqual(0);
        Options.Dpop.NonceRequired = false;
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
