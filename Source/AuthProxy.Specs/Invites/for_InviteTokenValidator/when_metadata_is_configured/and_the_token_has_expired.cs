// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Invites.for_InviteTokenValidator.when_metadata_is_configured;

public class and_the_token_has_expired : given.a_metadata_validated_token
{
    void Establish() => Token = CreateToken(expires: DateTime.UtcNow.AddHours(-1), notBefore: DateTime.UtcNow.AddHours(-2));
    async Task Because() => Result = await Validator.ValidateDetailed(Token, CancellationToken.None);
    [Fact] void should_distinguish_validly_signed_expiry() => Result.ShouldEqual(InviteTokenValidationResult.Expired);
}
