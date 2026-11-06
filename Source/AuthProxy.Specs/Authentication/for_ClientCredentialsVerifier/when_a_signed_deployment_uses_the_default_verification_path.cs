// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Authentication.for_ClientCredentialsVerifier;

public class when_a_signed_deployment_uses_the_default_verification_path : given.a_verifier
{
    protected override string VerificationPath => new C.ServiceClientCredentials().VerificationPath;

    Task Because() => Verify();

    [Fact] void should_allow_verification() => _result.Status.ShouldEqual(ClientCredentialsVerificationStatus.Succeeded);
    [Fact] void should_send_to_the_default_https_endpoint() => _handler.RequestedUris.Single().AbsoluteUri.ShouldEqual("https://backend.example/.cratis/client-credentials/verify");
}
