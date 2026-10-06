// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Invites.for_InvitationPageEmails.given;

public class an_email_bound_invitation : for_InviteMiddleware.given.an_invite_exchange
{
    protected string _invited = "invited@example.com";
    protected string? _asserted = "selected@example.com";
    protected string _page = string.Empty;
    protected IReadOnlyDictionary<string, string>? _substitutions;

    protected override string InviteEmailClaim => "recipient";

    protected virtual IReadOnlyList<Claim> ProviderClaims => _asserted is null ? [] : [new("email", _asserted), new("email_verified", "true")];

    void Establish() => _errorPageProvider.WriteErrorPageAsync(Arg.Any<HttpContext>(), Arg.Any<string>(), Arg.Any<int>(), Arg.Any<IReadOnlyDictionary<string, string>>()).Returns(call =>
    {
        _page = call.ArgAt<string>(1);
        _substitutions = call.ArgAt<IReadOnlyDictionary<string, string>?>(3);
        return Task.CompletedTask;
    });

    protected void GivenAnExchange()
    {
        GivenPendingInviteCookie(CreateSignedToken(claims: [new Claim(InviteEmailClaim, _invited)]));
        GivenAuthenticatedUserWith([.. ProviderClaims]);
    }
}
