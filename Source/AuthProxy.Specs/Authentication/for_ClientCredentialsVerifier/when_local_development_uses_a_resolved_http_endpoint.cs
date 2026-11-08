// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Authentication.for_ClientCredentialsVerifier;

public class when_local_development_uses_a_resolved_http_endpoint : given.a_verifier
{
    protected override C.DeploymentProfile Profile => C.DeploymentProfile.LocalDevelopment;

    protected override string VerificationPath => "http://localhost/verify";

    Task Because() => Verify();

    [Fact] void should_allow_verification() => _result.Status.ShouldEqual(ClientCredentialsVerificationStatus.Succeeded);
    [Fact] void should_call_the_resolved_endpoint() => _handler.RequestedUris.Single().AbsoluteUri.ShouldEqual("http://localhost/verify");
}
