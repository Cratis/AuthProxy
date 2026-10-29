// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Invites.for_InviteConfigurationValidator.when_token_metadata_is_configured;

public class and_the_url_is_plain_http_on_loopback : given.an_invite_configuration
{
    ValidateOptionsResult _result;

    void Because() => _result = Validate(new() { Invite = new() { TokenMetadataUrl = "http://127.0.0.1/metadata", Issuer = "issuer", Audience = "audience" } });

    [Fact] void should_accept_the_configuration() => _result.Succeeded.ShouldBeTrue();
}
