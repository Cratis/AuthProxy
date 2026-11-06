// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Authentication.for_ClientCredentialsVerifier;

public class when_a_signed_deployment_uses_a_resolved_https_endpoint : given.a_verifier
{
    protected override string VerificationPath => "https://verifier.example/verify";

    Task Because() => Verify();

    [Fact] void should_allow_verification() => _result.Status.ShouldEqual(ClientCredentialsVerificationStatus.Succeeded);
    [Fact] void should_call_the_resolved_endpoint() => _handler.RequestedUris.Single().AbsoluteUri.ShouldEqual("https://verifier.example/verify");
}
