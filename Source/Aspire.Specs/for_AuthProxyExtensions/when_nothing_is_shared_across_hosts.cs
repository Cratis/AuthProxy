// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Aspire.for_AuthProxyExtensions;

/// <summary>
/// An app host that never asks for a shared session must configure none, so the proxy keeps running with a host-only
/// cookie under its default name, a handshake per host and relative return URLs.
/// </summary>
public class when_nothing_is_shared_across_hosts : given.an_auth_proxy_resource
{
    Dictionary<string, string> _environment;

    void Establish() => _resource.WithActivityTimeout(TimeSpan.FromMinutes(1));

    async Task Because() => _environment = await EnvironmentVariables();

    [Fact] void should_not_declare_a_cookie_domain() => _environment.ContainsKey("Cratis__AuthProxy__Session__CookieDomain").ShouldBeFalse();
    [Fact] void should_not_declare_a_cookie_name() => _environment.ContainsKey("Cratis__AuthProxy__Session__CookieName").ShouldBeFalse();
    [Fact] void should_not_declare_a_callback_host() => _environment.ContainsKey("Cratis__AuthProxy__SignIn__CallbackHost").ShouldBeFalse();
}
