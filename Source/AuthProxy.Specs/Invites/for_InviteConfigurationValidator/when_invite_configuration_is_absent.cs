// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Invites.for_InviteConfigurationValidator;

public class when_invite_configuration_is_absent : given.an_invite_configuration
{
    ValidateOptionsResult _result;

    void Because() => _result = Validate(new C.AuthProxy { Invite = null });

    [Fact]
    void should_succeed() => _result.Succeeded.ShouldBeTrue();
}
