// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.Authentication;
using Microsoft.AspNetCore.Authentication;

namespace Cratis.AuthProxy.Identity.for_ClientPrincipalExtensions;

public class when_session_context_is_unavailable : given.a_recorded_session
{
    [Theory]
    [InlineData(null)]
    [InlineData("invalid")]
    [InlineData("-1")]
    public void should_not_invent_a_start(string? start)
    {
        _properties.Items[SessionStart.PropertyKey] = start;
        var result = _principal.WithSessionContext(_context);
        result.Claims.Any(_ => _.Type == SessionClaims.Started).ShouldBeFalse();
        result.Claims.Single(_ => _.Type == SessionClaims.SignInProvider).Value.ShouldEqual("microsoft");
    }

    [Theory]
    [InlineData("Bearer")]
    [InlineData("ClientCredentials")]
    [InlineData("Capability")]
    public void should_not_forward_context_for_a_non_cookie_credential(string scheme)
    {
        _context.Features.Set<IAuthenticateResultFeature>(new ResultFeature(AuthenticateResult.Success(new AuthenticationTicket(_context.User, _properties, scheme))));
        _principal.WithSessionContext(_context).ShouldBeSame(_principal);
    }

    [Fact]
    public void should_not_invent_a_missing_provider()
    {
        _properties.Items.Remove(SessionProvider.MarkerStateKey);
        var result = _principal.WithSessionContext(_context);
        result.Claims.Any(_ => _.Type == SessionClaims.SignInProvider).ShouldBeFalse();
        result.Claims.Single(_ => _.Type == SessionClaims.Started).Value.ShouldEqual("1700000000");
    }
}
