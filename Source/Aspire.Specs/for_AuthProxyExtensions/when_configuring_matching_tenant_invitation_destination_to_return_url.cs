// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Aspire.for_AuthProxyExtensions;

public class when_configuring_matching_tenant_invitation_destination_to_return_url : given.an_auth_proxy_resource
{
    Dictionary<string, string> _environment;

    void Establish() => _resource.WithMatchingTenantInvitationDestination(InvitationCompletionDestination.ReturnUrl);

    async Task Because() => _environment = await EnvironmentVariables();

    [Fact]
    void should_emit_the_enum_string_for_return_url() =>
        _environment["Cratis__AuthProxy__Invite__MatchingTenantInvitationDestination"].ShouldEqual("ReturnUrl");
}
