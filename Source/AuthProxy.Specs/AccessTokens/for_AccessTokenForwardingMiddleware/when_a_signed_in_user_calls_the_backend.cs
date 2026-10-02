// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.AccessTokens.for_AccessTokenForwardingMiddleware;

public class when_a_signed_in_user_calls_the_backend : given.a_forwarding_middleware
{
    Task Because() => Invoke();

    [Fact] void should_forward_the_request() => _forwarded.ShouldBeTrue();
    [Fact] void should_request_the_audience_from_the_selected_cluster() => _tokens.Received(1).GetFor("session-id", Arg.Is<C.ServiceAccessToken>(_ => _.Scopes.SequenceEqual(_accessToken.Scopes)), Arg.Any<CancellationToken>());
    [Fact] void should_replace_the_authorization_header_with_the_users_access_token() => _context.Request.Headers.Authorization.ToString().ShouldEqual("Bearer user-access-token");
}
