// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Invites.for_InviteMiddleware.when_invite_token_is_re_validated_at_exchange;

public class and_token_is_unsigned : given.an_invite_exchange
{
    void Establish()
    {
        GivenAuthenticatedUserWith();
        GivenPendingInviteCookie(CreateUnsignedToken());
    }

    async Task Because() => await _middleware.InvokeAsync(_context);

    [Fact] void should_not_forward_to_the_exchange_endpoint() => _exchangeCalled.ShouldBeFalse();
    [Fact] void should_not_continue_the_pipeline() => _nextCalled.ShouldBeFalse();
    [Fact] void should_serve_the_invitation_invalid_page() =>
        _errorPageProvider.Received(1).WriteErrorPageAsync(_context, WellKnownPageNames.InvitationInvalid, StatusCodes.Status401Unauthorized);

    static string CreateUnsignedToken()
    {
        // Models the exact threat: a self-crafted unsigned JWT (alg=none) with a future exp and a jti
        // equal to a known pending invitation id, placed in the .cratis-invite cookie after a normal login.
        var exp = DateTimeOffset.UtcNow.AddHours(1).ToUnixTimeSeconds();
        var header = Base64Url("{\"alg\":\"none\",\"typ\":\"JWT\"}");
        var payload = Base64Url($"{{\"jti\":\"known-invitation-id\",\"iss\":\"{Issuer}\",\"aud\":\"{Audience}\",\"exp\":{exp}}}");
        return $"{header}.{payload}.";
    }

    static string Base64Url(string value) =>
        Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes(value)).TrimEnd('=').Replace('+', '-').Replace('/', '_');
}
