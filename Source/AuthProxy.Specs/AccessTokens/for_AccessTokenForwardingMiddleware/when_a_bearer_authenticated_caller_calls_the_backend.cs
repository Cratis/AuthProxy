// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.AccessTokens.for_AccessTokenForwardingMiddleware;

public class when_a_bearer_authenticated_caller_calls_the_backend : given.a_forwarding_middleware
{
    void Establish() => _context.Items[Authentication.AuthenticationServiceCollectionExtensions.SelectedSchemeItemKey] = Authentication.ClientCredentialsDefaults.AuthenticationScheme;

    Task Because() => Invoke();

    [Fact] void should_forward_the_request() => _forwarded.ShouldBeTrue();
    [Fact] void should_keep_the_callers_own_authorization() => _context.Request.Headers.Authorization.ToString().ShouldEqual("Bearer something-the-browser-sent");
    [Fact] void should_obtain_no_user_token() => _tokens.DidNotReceive().GetFor(Arg.Any<string>(), Arg.Any<C.ServiceAccessToken>(), Arg.Any<CancellationToken>());
}
