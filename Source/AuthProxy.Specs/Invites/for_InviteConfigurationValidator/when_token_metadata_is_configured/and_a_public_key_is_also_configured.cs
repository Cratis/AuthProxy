// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Invites.for_InviteConfigurationValidator.when_token_metadata_is_configured;

public class and_a_public_key_is_also_configured : given.an_invite_configuration
{
    ValidateOptionsResult _result;

    void Because() => _result = Validate(new() { Invite = new() { TokenMetadataUrl = "https://lobby.example.com/metadata", Issuer = "issuer", Audience = "audience", PublicKeyPem = "pinned key" } });

    [Fact] void should_reject_the_configuration() => _result.Failed.ShouldBeTrue();
    [Fact] void should_name_the_public_key() => _result.FailureMessage.ShouldContain("Invite.PublicKeyPem");
}
