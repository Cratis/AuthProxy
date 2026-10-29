// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.ReverseProxy.for_ProxyOwnedCookiesTransform;

/// <summary>
/// A request with nothing but proxy cookies reaches the service without a cookie header.
/// </summary>
public class when_the_request_carries_only_proxy_cookies : given.a_proxied_request
{
    void Establish() => _cookies = [".Cratis.AuthProxy.Auth.v2=secret; .cratis-identity=x"];

    Task Because() => Apply();

    [Fact] void should_remove_the_cookie_header() => Forwarded.ShouldBeNull();
}
