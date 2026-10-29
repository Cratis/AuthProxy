// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.ReverseProxy.for_CallerAuthorizationHeaderTransform;

/// <summary>
/// A service that opts in receives the caller's header on a session request.
/// </summary>
public class when_the_service_forwards_the_caller_authorization_header : given.a_proxied_request
{
    void Establish() => _setting = C.CallerAuthorizationHeaderForwarding.Forward;

    Task Because() => Apply();

    [Fact] void should_keep_the_header() => HeaderForwarded.ShouldBeTrue();
}
