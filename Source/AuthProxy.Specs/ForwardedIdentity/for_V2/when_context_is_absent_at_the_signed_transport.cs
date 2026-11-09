// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.ForwardedIdentity.for_V2;

public class when_context_is_absent_at_the_signed_transport : for_ForwardedIdentitySigningHandler.given.a_signed_transport
{
    void Establish()
    {
        var v2 = when_signing_with_explicit_trusted_context.Settings();
        settings.Version = v2.Version;
        settings.PrivateKeyPkcs8Base64 = v2.PrivateKeyPkcs8Base64;
        settings.SecretBase64 = string.Empty;
    }

    Task Because() => Send();

    [Fact] void should_not_contact_the_backend() => transport.Calls.ShouldEqual(0);
    [Fact] void should_report_the_existing_typed_failure() => exception.ShouldBeOfExactType<ForwardedIdentityCouldNotBeSigned>();
    [Fact] void should_not_fall_back_to_any_proof() => request.Headers.Contains(Headers.ForwardedIdentitySignature).ShouldBeFalse();
}
