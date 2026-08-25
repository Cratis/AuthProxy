// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Aspire.for_AuthProxyExtensions;

public class when_configuring_matching_tenant_invitation_redirects : given.an_auth_proxy_resource
{
    Dictionary<string, string> _environment;

    void Establish() => _resource.WithTenantIssuedInvitesSkipLobby(false);

    async Task Because() => _environment = await EnvironmentVariables();

    [Fact]
    void should_emit_the_exact_skip_lobby_setting() =>
        _environment["Cratis__AuthProxy__Invite__TenantIssuedInvitesSkipLobby"].ShouldEqual(bool.FalseString);
}
