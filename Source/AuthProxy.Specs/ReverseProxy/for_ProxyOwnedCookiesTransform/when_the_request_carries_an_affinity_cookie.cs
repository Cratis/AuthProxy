// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.ReverseProxy.for_ProxyOwnedCookiesTransform;

/// <summary>
/// The affinity cookie of a configured service is AuthProxy's own and never reaches a backend, while a cookie that
/// merely starts with its name is the application's.
/// </summary>
public class when_the_request_carries_an_affinity_cookie : given.a_proxied_request
{
    void Establish()
    {
        _services = new() { ["Reporting"] = new() };
        _cookies = [".cratis-affinity-reporting=x; .cratis-affinity-reportingx=1; app=2"];
    }

    Task Because() => Apply();

    [Fact] void should_remove_only_the_exact_affinity_cookie() => Forwarded.ShouldEqual(".cratis-affinity-reportingx=1; app=2");
}
