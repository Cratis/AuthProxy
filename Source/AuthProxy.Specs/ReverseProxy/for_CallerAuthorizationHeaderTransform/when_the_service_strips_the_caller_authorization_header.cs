// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.ReverseProxy.for_CallerAuthorizationHeaderTransform;

/// <summary>
/// A service that strips the header never receives the caller's own, even without a session.
/// </summary>
public class when_the_service_strips_the_caller_authorization_header : given.a_proxied_request
{
    void Establish() => (_authenticated, _scheme, _setting) = (false, null, C.CallerAuthorizationHeaderForwarding.Strip);

    Task Because() => Apply();

    [Fact] void should_remove_the_header() => HeaderForwarded.ShouldBeFalse();
}
