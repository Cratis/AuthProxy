// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Text;
using System.Text.Json;
using Cratis.AuthProxy.ForwardedIdentity;

namespace Cratis.AuthProxy.BearerRoutes.for_DpopProofVerifier;

public class when_enforcing_dpop : given_a_dpop_gate
{
    [Fact]
    public async Task should_forward_only_after_consumption_and_carry_standard_base64_sender_evidence()
    {
        BearerForwardedIdentity? captured = null;
        Forwarder.Forward(Arg.Any<HttpContext>(), Arg.Any<ResolvedBearerRoute>(), Arg.Any<BearerForwardedIdentity>())
            .Returns(call =>
            {
                captured = call.Arg<BearerForwardedIdentity>();
                return Task.CompletedTask;
            });
        var request = Request();
        request.Request.Headers["Forwarded"] = "host=attacker.example.test;proto=http";
        request.Request.Headers["X-Forwarded-Host"] = "attacker.example.test";
        await Gate.InvokeAsync(request);
        Store.Count.ShouldEqual(1);
        captured.ShouldNotBeNull();
        using var evidence = JsonDocument.Parse(Encoding.UTF8.GetString(Convert.FromBase64String(captured.SenderBinding)));
        evidence.RootElement.GetProperty("jkt").GetString().ShouldEqual(Jkt);
        evidence.RootElement.GetProperty("jti").GetString().ShouldEqual((string)Payload["jti"]);
        var trusted = new ForwardedIdentityTrustedContext("machine-principal", "synthetic-credential", captured.SenderBinding);
        ForwardedIdentityV2ContextHeaders.TryHeaders(trusted, out var headers).ShouldBeTrue();
        headers["x-cratis-sender-binding"].ShouldEqual(captured.SenderBinding);
    }

    [Fact]
    public async Task should_refuse_a_bound_token_presented_as_bearer()
    {
        var request = Request(scheme: "Bearer");
        await Gate.InvokeAsync(request);
        Refused(request, 401);
        request.Response.Headers.WWWAuthenticate.ToString().ShouldContain("DPoP");
        Store.Count.ShouldEqual(0);
    }

    [Theory]
    [InlineData("htm", "GET")]
    [InlineData("htu", "https://attacker.example.test/mcp")]
    [InlineData("ath", "wrong")]
    public async Task should_never_forward_a_wrong_per_request_claim(string claim, string value)
    {
        Payload[claim] = value;
        var request = Request();
        await Gate.InvokeAsync(request);
        Refused(request, 401);
        Store.Count.ShouldEqual(0);
    }

    [Fact]
    public async Task should_refuse_reused_identifiers_across_replicas_atomically()
    {
        var proof = Proof();
        var requests = Enumerable.Range(0, 24).Select(_ => Request(proof)).ToArray();
        var replicas = new[] { Gate, Replica() };
        await Task.WhenAll(requests.Select((request, index) => Task.Run(() => replicas[index % 2].InvokeAsync(request))));
        Store.Count.ShouldEqual(1);
        requests.Count(request => request.Response.StatusCode == 200).ShouldEqual(1);
        requests.Count(request => request.Response.StatusCode == 401).ShouldEqual(23);
        await Forwarder.Received(1).Forward(Arg.Any<HttpContext>(), Arg.Any<ResolvedBearerRoute>(), Arg.Any<BearerForwardedIdentity>());
    }

    [Fact]
    public async Task should_require_a_nonce_then_accept_it_once_across_replicas()
    {
        Options.Dpop.NonceRequired = true;
        var request = Request();
        await Gate.InvokeAsync(request);
        Refused(request, 401, "use_dpop_nonce");
        Store.Count.ShouldEqual(0);
        Payload["nonce"] = request.Response.Headers["DPoP-Nonce"].ToString();
        var accepted = Request();
        await Replica().InvokeAsync(accepted);
        accepted.Response.StatusCode.ShouldEqual(200);
        Store.Count.ShouldEqual(1);
        var repeated = Request();
        await Gate.InvokeAsync(repeated);
        repeated.Response.StatusCode.ShouldEqual(401);
    }

    [Fact]
    public async Task should_refuse_multiple_proof_headers()
    {
        var request = Request();
        request.Request.Headers["DPoP"] = new[] { Proof(), Proof() };
        await Gate.InvokeAsync(request);
        Refused(request, 401);
    }

    [Theory]
    [InlineData(false, 0)]
    [InlineData(true, 31)]
    [InlineData(true, -31)]
    public async Task should_fail_closed_without_store_health_and_not_issue_a_nonce(bool available, long clockOffset)
    {
        Store.Available = available;
        Store.ClockOffset = clockOffset;
        Options.Dpop.NonceRequired = true;
        var request = Request();
        await Gate.InvokeAsync(request);
        Refused(request, 401);
        request.Response.Headers["DPoP-Nonce"].ToString().ShouldBeEmpty();
    }
}
