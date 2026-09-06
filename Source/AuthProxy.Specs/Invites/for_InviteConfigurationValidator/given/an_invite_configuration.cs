// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Invites.for_InviteConfigurationValidator.given;

public class an_invite_configuration : Specification
{
    protected static ValidateOptionsResult Validate(C.AuthProxy configuration) =>
        new InviteConfigurationValidator().Validate(null, configuration);
}
