// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.ReverseProxy.for_CallerAuthorizationHeaderTransform;

/// <summary>
/// A route the operator listed for passthrough keeps the caller's own header even when a session cookie is present.
/// </summary>
public class when_a_listed_anonymous_route_carries_a_session_cookie_and_an_authorization_header : given.a_proxied_request
{
    void Establish() => (_setting, _passesCallerAuthorization) = (C.CallerAuthorizationHeaderForwarding.Default, true);

    Task Because() => Apply();

    [Fact] void should_keep_the_header() => HeaderForwarded.ShouldBeTrue();
    [Fact] void should_not_change_the_value() => _transformContext.ProxyRequest.Headers.Authorization!.Parameter.ShouldEqual("callers-own-token");
}
