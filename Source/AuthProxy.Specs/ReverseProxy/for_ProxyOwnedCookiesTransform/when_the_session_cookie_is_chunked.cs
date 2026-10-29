// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.ReverseProxy.for_ProxyOwnedCookiesTransform;

/// <summary>
/// Every chunk of the session cookie is removed with it.
/// </summary>
public class when_the_session_cookie_is_chunked : given.a_proxied_request
{
    void Establish() => _cookies = [".Cratis.AuthProxy.Auth.v2C1=a; theme=dark; .Cratis.AuthProxy.Auth.v2C2=b; .Cratis.AuthProxy.Auth.v2=c"];

    Task Because() => Apply();

    [Fact] void should_remove_the_cookie_and_its_chunks() => Forwarded.ShouldEqual("theme=dark");
}
