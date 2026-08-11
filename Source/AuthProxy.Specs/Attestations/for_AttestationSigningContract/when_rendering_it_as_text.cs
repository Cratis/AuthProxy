// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Attestations.for_AttestationSigningContract;

/// <summary>
/// The contract is a record, and a record's generated rendering prints every one of its properties — including
/// the signing key. One <c>LogDebug("{Contract}", contract)</c> added by anyone, at any point, would write the
/// private key to the log without a single line of code looking wrong. The rendering has to be safe by
/// construction rather than by everybody remembering.
/// </summary>
public class when_rendering_it_as_text : Specification
{
    const string Issuer = "https://auth.example.com";
    const string Audience = "ada";
    const string KeyId = "sign-in-2026-08";
    const string PrivateKeyPem = "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQ\n-----END PRIVATE KEY-----";

    readonly AttestationSigningContract _contract = new(Issuer, Audience, KeyId, PrivateKeyPem, TimeSpan.FromSeconds(60));
    string _text;

    void Because() => _text = _contract.ToString();

    [Fact] void should_not_disclose_the_private_key() => _text.Contains(PrivateKeyPem, StringComparison.Ordinal).ShouldBeFalse();
    [Fact] void should_not_disclose_a_fragment_of_the_private_key() => _text.Contains("MIIEvQIBADANBgkqhkiG9w0BAQ", StringComparison.Ordinal).ShouldBeFalse();
    [Fact] void should_still_name_the_signing_key() => _text.Contains(KeyId, StringComparison.Ordinal).ShouldBeTrue();
    [Fact] void should_still_name_the_issuer() => _text.Contains(Issuer, StringComparison.Ordinal).ShouldBeTrue();
    [Fact] void should_still_name_the_audience() => _text.Contains(Audience, StringComparison.Ordinal).ShouldBeTrue();
}
