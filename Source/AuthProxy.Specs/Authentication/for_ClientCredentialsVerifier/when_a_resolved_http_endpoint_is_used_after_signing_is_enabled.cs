// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Net;

namespace Cratis.AuthProxy.Authentication.for_ClientCredentialsVerifier;

public class when_a_resolved_http_endpoint_is_used_after_signing_is_enabled : given.a_verifier
{
    Task Because() => Verify();

    [Fact] void should_fail_verification() => _result.Status.ShouldEqual(ClientCredentialsVerificationStatus.Failed);
    [Fact] void should_preserve_the_unavailable_status() => _result.StatusCode.ShouldEqual(HttpStatusCode.BadGateway);
    [Fact] void should_not_create_a_client() => _factory.DidNotReceive().CreateClient(Arg.Any<string>());
    [Fact] void should_not_send_the_request() => _handler.Calls.ShouldEqual(0);
}
