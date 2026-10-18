// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Security.Cryptography;
using Cratis.AuthProxy.Admission.given;
using Cratis.AuthProxy.ForwardedIdentity.given;
using Microsoft.Extensions.Logging.Abstractions;

namespace Cratis.AuthProxy.ForwardedIdentity.for_ForwardedIdentityToken;

/// <summary>
/// The verifier is implemented in another repository from the same text, and these vectors are committed to both,
/// byte for byte. They are the contract test: if AuthProxy's canonical string, digest or signing input drifts from
/// them, the two halves no longer agree. ECDSA signatures are randomized, so the token is checked by verifying it,
/// never by comparing it.
/// </summary>
public class when_reproducing_the_golden_vectors : Specification
{
    GoldenVectors _vectors;
    bool _canonicalized;
    string _canonical;
    string? _subject;
    string? _tenant;
    string _signingInput;
    string _completed;
    Assertion _fromSigner;
    ForwardedIdentitySigningStatus _status;

    void Establish() => _vectors = GoldenVectors.Load();

    void Because()
    {
        using var request = _vectors.Request();
        _canonicalized = ForwardedIdentityToken.TryCanonicalize(request.Headers, out _canonical, out _subject, out _tenant);
        _signingInput = ForwardedIdentityToken.SigningInput(
            _vectors.KeyId,
            new ForwardedIdentityClaims(
                _vectors.Issuer,
                _vectors.Audience,
                _vectors.IssuedAt,
                _vectors.IssuedAt + _vectors.LifetimeSeconds,
                _vectors.Jti,
                _vectors.Method,
                _vectors.Path,
                _subject,
                _tenant,
                ForwardedIdentityToken.Digest(_canonical)));

        using var key = ECDsa.Create();
        key.ImportFromPem(_vectors.PrivateKeyPem);
        _completed = ForwardedIdentityToken.Complete(_signingInput, key);

        _status = SignWithTheSigner(request);
        _fromSigner = Assertion.Parse(request.Headers.GetValues(Headers.ForwardedIdentity).Single());
    }

    [Fact] void should_canonicalize_the_headers() => _canonicalized.ShouldBeTrue();
    [Fact] void should_produce_the_canonical_header_string() => _canonical.ShouldEqual(_vectors.Canonical);
    [Fact] void should_produce_the_header_digest() => ForwardedIdentityToken.Digest(_canonical).ShouldEqual(_vectors.Fwh);
    [Fact] void should_produce_the_signing_input() => _signingInput.ShouldEqual(_vectors.SigningInput);
    [Fact] void should_carry_the_signing_input_in_the_committed_token() => Assertion.Parse(_vectors.Token).SigningInput.ShouldEqual(_vectors.SigningInput);
    [Fact] void should_carry_the_protected_header_in_the_committed_token() => Assertion.Parse(_vectors.Token).ProtectedHeader.ShouldEqual(_vectors.ProtectedHeader);
    [Fact] void should_carry_the_payload_in_the_committed_token() => Assertion.Parse(_vectors.Token).Payload.ShouldEqual(_vectors.Payload);
    [Fact] void should_verify_the_committed_token() => Assertion.Parse(_vectors.Token).VerifiesWith(_vectors.PublicKeyPem).ShouldBeTrue();
    [Fact] void should_verify_a_token_completed_with_the_vector_key() => Assertion.Parse(_completed).VerifiesWith(_vectors.PublicKeyPem).ShouldBeTrue();
    [Fact] void should_sign_the_vector_request_with_the_signer() => _status.ShouldEqual(ForwardedIdentitySigningStatus.Attested);
    [Fact] void should_write_the_vector_header_from_the_signer() => _fromSigner.ProtectedHeader.ShouldEqual(_vectors.ProtectedHeader);
    [Fact] void should_write_the_vector_payload_from_the_signer_but_for_the_identifier() => WithoutIdentifier(_fromSigner.Payload).ShouldEqual(WithoutIdentifier(_vectors.Payload));
    [Fact] void should_verify_the_signer_token_with_the_vector_key() => _fromSigner.VerifiesWith(_vectors.PublicKeyPem).ShouldBeTrue();

    static string WithoutIdentifier(string payload)
    {
        const string claim = "\"jti\":\"";
        var start = payload.IndexOf(claim, StringComparison.Ordinal) + claim.Length;
        var end = payload.IndexOf('"', start);
        return string.Concat(payload.AsSpan(0, start), payload.AsSpan(end));
    }

    ForwardedIdentitySigningStatus SignWithTheSigner(HttpRequestMessage request)
    {
        var configuration = new C.AuthProxy
        {
            ForwardingAttestation = new C.ForwardingAttestation
            {
                Issuer = _vectors.Issuer,
                ActiveKeyId = _vectors.KeyId,
                Lifetime = TimeSpan.FromSeconds(_vectors.LifetimeSeconds),
                SigningKeys = [new C.ForwardingAttestationSigningKey { KeyId = _vectors.KeyId, PrivateKeyPem = _vectors.PrivateKeyPem }],
            },
        };
        var config = Substitute.For<IOptionsMonitor<C.AuthProxy>>();
        config.CurrentValue.Returns(configuration);
        using var signer = new ForwardedIdentitySigner(config, new FixedTime(DateTimeOffset.FromUnixTimeSeconds(_vectors.IssuedAt)), NullLogger<ForwardedIdentitySigner>.Instance);
        return signer.Sign(request, _vectors.Audience);
    }
}
