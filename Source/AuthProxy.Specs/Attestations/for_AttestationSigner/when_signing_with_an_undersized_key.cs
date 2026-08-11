// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Security.Cryptography;

namespace Cratis.AuthProxy.Attestations.for_AttestationSigner;

/// <summary>
/// Microsoft.IdentityModel signs with a 1024-bit RSA key without complaint, so nothing about the resulting
/// assertion says it is weak — it verifies, and every binding it carries reads exactly as it should. The floor
/// therefore has to be enforced by the signer itself: this method is public, so the configuration validator is
/// not the only way into it.
/// </summary>
public class when_signing_with_an_undersized_key : Specification
{
    bool _undersized;
    bool _conformant;
    string _fromUndersizedKey;
    string _fromConformantKey;

    void Because()
    {
        _undersized = AttestationSigner.TryIssue(Contract(1024), DateTimeOffset.UtcNow, Claims(), out _fromUndersizedKey);
        _conformant = AttestationSigner.TryIssue(Contract(2048), DateTimeOffset.UtcNow, Claims(), out _fromConformantKey);
    }

    [Fact] void should_refuse_to_sign_with_an_undersized_key() => _undersized.ShouldBeFalse();
    [Fact] void should_hand_back_nothing_it_refused_to_sign() => _fromUndersizedKey.ShouldBeEmpty();
    [Fact] void should_sign_with_a_conformant_key() => _conformant.ShouldBeTrue();
    [Fact] void should_hand_back_the_assertion_it_signed() => _fromConformantKey.ShouldNotBeEmpty();

    static AttestationSigningContract Contract(int keySize)
    {
        using var rsa = RSA.Create(keySize);
        return new("https://auth.example.com", "ada", "current", rsa.ExportPkcs8PrivateKeyPem(), TimeSpan.FromSeconds(60));
    }

    static Dictionary<string, object> Claims() => new(StringComparer.Ordinal) { ["purpose"] = "specification" };
}
