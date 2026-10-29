// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.ReverseProxy.for_ProxyOwnedCookiesTransform;

/// <summary>
/// Only exact names are removed, so an application cookie that merely starts with a proxy cookie name is kept.
/// </summary>
public class when_an_application_cookie_shares_a_prefix_with_a_proxy_cookie : given.a_proxied_request
{
    void Establish() => _cookies = [".cratis-tenant-x=1; .cratis-tenant=2; .Cratis.AuthProxy.Auth.v2X=3"];

    Task Because() => Apply();

    [Fact] void should_keep_the_application_cookies() => Forwarded.ShouldEqual(".cratis-tenant-x=1; .Cratis.AuthProxy.Auth.v2X=3");
}
