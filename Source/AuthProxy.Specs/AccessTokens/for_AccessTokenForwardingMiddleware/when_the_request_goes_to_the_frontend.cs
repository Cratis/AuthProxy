// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.AccessTokens.for_AccessTokenForwardingMiddleware;

public class when_the_request_goes_to_the_frontend : given.a_forwarding_middleware
{
    void Establish() => _endpoint = ReverseProxy.MicroserviceReverseProxyConfigProvider.FrontendEndpoint;

    Task Because() => Invoke();

    [Fact] void should_forward_the_request() => _forwarded.ShouldBeTrue();
    [Fact] void should_obtain_no_user_token() => _tokens.DidNotReceive().GetFor(Arg.Any<string>(), Arg.Any<C.ServiceAccessToken>(), Arg.Any<CancellationToken>());
}
