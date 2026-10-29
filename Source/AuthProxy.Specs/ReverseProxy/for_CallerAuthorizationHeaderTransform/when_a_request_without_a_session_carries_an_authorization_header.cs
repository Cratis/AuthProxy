// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.ReverseProxy.for_CallerAuthorizationHeaderTransform;

/// <summary>
/// A request with no session, such as one to an anonymous path, keeps the caller's header by default.
/// </summary>
public class when_a_request_without_a_session_carries_an_authorization_header : given.a_proxied_request
{
    void Establish() => (_authenticated, _scheme) = (false, null);

    Task Because() => Apply();

    [Fact] void should_keep_the_header() => HeaderForwarded.ShouldBeTrue();
}
