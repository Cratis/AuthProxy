// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.IdentityModel.Tokens;

namespace Cratis.AuthProxy.Invites.for_InviteTokenValidator.when_metadata_is_configured;

public class and_the_kid_appears_after_refresh : given.a_metadata_validated_token
{
    void Establish() => Keys.GetSigningKeys(Invite, Arg.Any<CancellationToken>(), false).Returns(Task.FromResult<IReadOnlyDictionary<string, SecurityKey>?>(new Dictionary<string, SecurityKey>()));
    async Task Because() => Result = await Validator.ValidateDetailed(Token, CancellationToken.None);
    [Fact] void should_accept() => Result.ShouldEqual(InviteTokenValidationResult.Valid);
    [Fact] void should_refresh_once() => Keys.Received(1).GetSigningKeys(Invite, Arg.Any<CancellationToken>(), true);
}
