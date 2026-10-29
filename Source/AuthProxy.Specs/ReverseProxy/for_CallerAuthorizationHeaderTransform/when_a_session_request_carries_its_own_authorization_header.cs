// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.ReverseProxy.for_CallerAuthorizationHeaderTransform;

/// <summary>
/// The caller's header is not forwarded on a request authenticated by the session.
/// </summary>
public class when_a_session_request_carries_its_own_authorization_header : given.a_proxied_request
{
    void Establish() => _setting = C.CallerAuthorizationHeaderForwarding.Default;

    Task Because() => Apply();

    [Fact] void should_remove_the_header() => HeaderForwarded.ShouldBeFalse();
}
