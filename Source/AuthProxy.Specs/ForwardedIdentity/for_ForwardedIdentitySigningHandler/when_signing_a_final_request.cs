// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.ForwardedIdentity.for_ForwardedIdentitySigningHandler;

public class when_signing_a_final_request : given.a_signed_transport
{
    string _firstProof;
    void Establish() => request.Headers.Add(Headers.ForwardedIdentitySignature, "stale");
    async Task Because()
    {
        await Send();
        _firstProof = proof;
        await Send();
    }
    [Fact] void should_send_both_requests() => transport.Calls.ShouldEqual(2);
    [Fact] void should_replace_the_stale_proof() => proof.StartsWith("v1.key-1.1700000000.", StringComparison.Ordinal).ShouldBeTrue();
    [Fact] void should_emit_exactly_one_proof() => request.Headers.GetValues(Headers.ForwardedIdentitySignature).Count().ShouldEqual(1);
    [Fact] void should_use_a_fresh_nonce_for_identical_requests() => proof.Split('.')[3].ShouldNotEqual(_firstProof.Split('.')[3]);
    [Fact]
    void should_emit_43_character_nonce_and_mac()
    {
        proof.Split('.')[3].Length.ShouldEqual(43);
        proof.Split('.')[4].Length.ShouldEqual(43);
    }
    [Fact]
    void should_bind_the_final_path_and_headers()
    {
        var parts = proof.Split('.');
        ForwardedIdentityCanonicalInput.TryCreate(request, settings.Audience, settings.KeyId, parts[2], parts[3], out var canonical, out _).ShouldBeTrue();
        parts[4].ShouldEqual(ForwardedIdentityEnvelope.Mac(Convert.FromBase64String(settings.SecretBase64), canonical));
    }
}
