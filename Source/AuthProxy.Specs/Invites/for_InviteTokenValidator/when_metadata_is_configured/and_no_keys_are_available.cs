// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.IdentityModel.Tokens;

namespace Cratis.AuthProxy.Invites.for_InviteTokenValidator.when_metadata_is_configured;

public class and_no_keys_are_available : given.a_metadata_validated_token
{
    void Establish() => Keys.GetSigningKeys(Invite, Arg.Any<CancellationToken>(), false).Returns(Task.FromResult<IReadOnlyDictionary<string, SecurityKey>?>(null));
    async Task Because() => Result = await Validator.ValidateDetailed(Token, CancellationToken.None);
    [Fact] void should_reject_the_token() => Result.ShouldEqual(InviteTokenValidationResult.Invalid);
    [Fact] void should_not_retry_an_unavailable_issuer() => Keys.DidNotReceive().GetSigningKeys(Invite, Arg.Any<CancellationToken>(), true);
}
