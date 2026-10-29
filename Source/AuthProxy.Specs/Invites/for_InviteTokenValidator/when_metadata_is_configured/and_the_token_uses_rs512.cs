// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.IdentityModel.Tokens;

namespace Cratis.AuthProxy.Invites.for_InviteTokenValidator.when_metadata_is_configured;

public class and_the_token_uses_rs512 : given.a_metadata_validated_token
{
    void Establish() => Token = WithAlgorithm(SecurityAlgorithms.RsaSha512, SigningKey);
    async Task Because() => Result = await Validator.ValidateDetailed(Token, CancellationToken.None);
    [Fact] void should_reject() => Result.ShouldEqual(InviteTokenValidationResult.Invalid);
    [Fact] void should_not_fetch_keys() => Keys.ReceivedCalls().ShouldBeEmpty();
}
