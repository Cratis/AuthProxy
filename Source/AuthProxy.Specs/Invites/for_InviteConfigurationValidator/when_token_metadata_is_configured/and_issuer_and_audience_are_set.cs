// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Invites.for_InviteConfigurationValidator.when_token_metadata_is_configured;

public class and_issuer_and_audience_are_set : given.an_invite_configuration
{
    ValidateOptionsResult _result;

    void Because() => _result = Validate(new() { Invite = new() { TokenMetadataUrl = "https://lobby.example.com/metadata", Issuer = "issuer", Audience = "audience" } });

    [Fact] void should_accept_the_configuration() => _result.Succeeded.ShouldBeTrue();
}
