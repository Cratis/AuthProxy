// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Aspire.for_AuthProxyExtensions;

public class when_sharing_the_session_across_hosts : given.an_auth_proxy_resource
{
    Dictionary<string, string> _environment;

    void Establish()
    {
        _resource.WithSessionCookieDomain(".example.com");
        _resource.WithSessionCookieName(".Example.Auth");
        _resource.WithSignInCallbackHost("auth.example.com");
    }

    async Task Because() => _environment = await EnvironmentVariables();

    [Fact] void should_declare_the_cookie_domain() => _environment["Cratis__AuthProxy__Session__CookieDomain"].ShouldEqual(".example.com");
    [Fact] void should_declare_the_cookie_name() => _environment["Cratis__AuthProxy__Session__CookieName"].ShouldEqual(".Example.Auth");
    [Fact] void should_declare_the_callback_host() => _environment["Cratis__AuthProxy__SignIn__CallbackHost"].ShouldEqual("auth.example.com");
}
