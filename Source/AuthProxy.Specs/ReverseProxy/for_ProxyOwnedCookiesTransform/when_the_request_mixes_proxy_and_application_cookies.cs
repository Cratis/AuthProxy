// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.ReverseProxy.for_ProxyOwnedCookiesTransform;

/// <summary>
/// Cookies that belong to the proxy stay with the proxy and the application's own cookies arrive unchanged.
/// </summary>
public class when_the_request_mixes_proxy_and_application_cookies : given.a_proxied_request
{
    void Establish() => _cookies = [".Cratis.AuthProxy.Auth.v2=secret; theme=dark; .cratis-tenant=abc; lang=en; .cratis-tenants=x"];

    Task Because() => Apply();

    [Fact] void should_forward_only_the_application_cookies_in_order() => Forwarded.ShouldEqual("theme=dark; lang=en");
}
