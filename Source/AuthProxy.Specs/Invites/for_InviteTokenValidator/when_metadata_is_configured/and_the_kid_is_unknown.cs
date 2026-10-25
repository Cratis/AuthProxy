// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Invites.for_InviteTokenValidator.when_metadata_is_configured;

public class and_the_kid_is_unknown : given.a_metadata_validated_token
{
    void Establish() => PublicKeys.Clear();
    async Task Because() => Result = await Validator.ValidateDetailed(Token, CancellationToken.None);
    [Fact] void should_reject() => Result.ShouldEqual(InviteTokenValidationResult.Invalid);
    [Fact] void should_request_only_one_refresh() => Keys.Received(1).GetSigningKeys(Invite, Arg.Any<CancellationToken>(), true);
}
