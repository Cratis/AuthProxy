// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.ReverseProxy.for_ProxyOwnedCookiesTransform;

/// <summary>
/// The configured session cookie is removed, and the default name is then an ordinary application cookie.
/// </summary>
public class when_the_session_cookie_name_is_configured : given.a_proxied_request
{
    void Establish()
    {
        _sessionCookieName = "my-session";
        _cookies = ["my-session=secret; .Cratis.AuthProxy.Auth.v2=other; theme=dark"];
    }

    Task Because() => Apply();

    [Fact] void should_remove_the_configured_cookie_only() => Forwarded.ShouldEqual(".Cratis.AuthProxy.Auth.v2=other; theme=dark");
}
