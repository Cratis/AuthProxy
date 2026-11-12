// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Text.Json;
using Microsoft.AspNetCore.Authentication;

namespace Cratis.AuthProxy.Authentication.for_AuthenticationServiceCollectionExtensions;

/// <summary>
/// Specifies the admission decision for principals built the way the OIDC handler builds them: ID-token claims plus the registered user-info claim actions run over a real user-info document.
/// </summary>
public class when_an_oidc_callback_merges_id_token_and_user_info_claims : given.gated_oidc_providers
{
    TicketReceivedContext _agreeingDuplicates;
    TicketReceivedContext _userInfoBoolean;
    TicketReceivedContext _userInfoText;
    TicketReceivedContext _userInfoFalse;
    TicketReceivedContext _userInfoWithoutFlag;
    TicketReceivedContext _differingAddresses;
    TicketReceivedContext _differingFlags;

    async Task Because()
    {
        _agreeingDuplicates = await Receive(
            [("sub", "s"), ("email", "a@b.c"), ("email_verified", "true")],
            """{"sub":"s","email":"a@b.c","email_verified":true}""");
        _userInfoBoolean = await Receive([("sub", "s")], """{"sub":"s","email":"a@b.c","email_verified":true}""");
        _userInfoText = await Receive([("sub", "s")], """{"sub":"s","email":"a@b.c","email_verified":"true"}""");
        _userInfoFalse = await Receive([("sub", "s")], """{"sub":"s","email":"a@b.c","email_verified":false}""");
        _userInfoWithoutFlag = await Receive([("sub", "s")], """{"sub":"s","email":"a@b.c"}""");
        _differingAddresses = await Receive(
            [("sub", "s"), ("email", "a@b.c"), ("email_verified", "true")],
            """{"sub":"s","email":"x@y.z","email_verified":true}""");
        _differingFlags = await Receive(
            [("sub", "s"), ("email", "a@b.c"), ("email_verified", "true")],
            """{"sub":"s","email":"a@b.c","email_verified":false}""");
    }

    [Fact] void should_admit_the_same_address_and_flag_from_the_id_token_and_user_info() => Admitted(_agreeingDuplicates).ShouldBeTrue();
    [Fact] void should_admit_a_json_boolean_from_user_info() => Admitted(_userInfoBoolean).ShouldBeTrue();
    [Fact] void should_admit_a_textual_flag_from_user_info() => Admitted(_userInfoText).ShouldBeTrue();
    [Fact] void should_refuse_a_false_flag_from_user_info() => Admitted(_userInfoFalse).ShouldBeFalse();
    [Fact] void should_refuse_user_info_without_the_flag() => Admitted(_userInfoWithoutFlag).ShouldBeFalse();
    [Fact] void should_refuse_differing_addresses() => Admitted(_differingAddresses).ShouldBeFalse();
    [Fact] void should_refuse_differing_flags() => Admitted(_differingFlags).ShouldBeFalse();

    static bool Admitted(TicketReceivedContext context) => context.Result?.Handled != true;

    async Task<TicketReceivedContext> Receive((string Type, string Value)[] idTokenClaims, string userInfo)
    {
        var principal = PrincipalWith(idTokenClaims);
        using var document = JsonDocument.Parse(userInfo);
        foreach (var action in _strictOptions.ClaimActions)
        {
            action.Run(document.RootElement, (ClaimsIdentity)principal.Identity!, "https://login.example.com/tenant");
        }
        return await ReceiveTicket(Context(), "strict", _strictOptions, principal);
    }
}
