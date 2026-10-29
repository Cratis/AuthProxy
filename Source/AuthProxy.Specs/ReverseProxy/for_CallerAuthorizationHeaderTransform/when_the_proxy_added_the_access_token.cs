// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.ReverseProxy.for_CallerAuthorizationHeaderTransform;

/// <summary>
/// A token AuthProxy wrote itself is always forwarded.
/// </summary>
public class when_the_proxy_added_the_access_token : given.a_proxied_request
{
    void Establish() => _proxyWroteHeader = true;

    Task Because() => Apply();

    [Fact] void should_keep_the_header() => HeaderForwarded.ShouldBeTrue();
}
