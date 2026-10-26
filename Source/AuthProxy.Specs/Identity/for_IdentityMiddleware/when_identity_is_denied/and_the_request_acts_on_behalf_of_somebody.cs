// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.Arc.Identity;
using Cratis.AuthProxy.OnBehalfSessions;

namespace Cratis.AuthProxy.Identity.for_IdentityMiddleware.when_identity_is_denied;

/// <summary>
/// During an on-behalf session the identity the application refused is the represented user's. The on-behalf session
/// ends; the actor's own session is not theirs to lose over it, even where the deployment terminates sessions on denial.
/// </summary>
public class and_the_request_acts_on_behalf_of_somebody : given.an_identity_middleware
{
    IOnBehalfSessions _onBehalfSessions;
    ClientPrincipal _represented;

    void Establish()
    {
        ResolveTenant();
        EnableSessionTermination();
        _represented = new ClientPrincipal { IdentityProvider = "microsoft", UserId = "represented-user", UserDetails = "user@example.com" };
        _context.SetOnBehalf(new OnBehalfContext(
            new OnBehalfSession("session-1", new OnBehalfActor("aad", "user-1", "User One"), TenantId, "represented-user", "ISSUE-1", DateTimeOffset.UtcNow, DateTimeOffset.UtcNow.AddHours(1)),
            _represented,
            "actor",
            "assertion"));
        _context.Request.Headers.Cookie = $"{Cookies.OnBehalf}=protected";

        _onBehalfSessions = Substitute.For<IOnBehalfSessions>();
        _context.RequestServices.GetService(typeof(IOnBehalfSessions)).Returns(_onBehalfSessions);

        _resolver
            .Resolve(Arg.Any<HttpContext>(), Arg.Any<ClientPrincipal>(), Arg.Any<string>())
            .Returns(_ => new IdentityProviderResult("represented-user", "User", true, false, [], new object()));
    }

    async Task Because() => await _middleware.InvokeAsync(_context);

    [Fact] void should_ask_about_the_represented_user() => _resolver.Received(1).Resolve(_context, _represented, TenantId);
    [Fact] void should_end_the_on_behalf_session() => _onBehalfSessions.Received(1).End(_context, OnBehalfSessionEndReason.RepresentedIdentityDenied);
    [Fact] void should_say_why_it_ended() => _context.Response.Headers[Headers.OnBehalfEnded].ToString().ShouldEqual("represented-identity-denied");
    [Fact] void should_preserve_the_actors_own_session() => ShouldHavePreservedSession();
    [Fact] void should_still_refuse_the_request() => ShouldHaveBeenRefused();
    [Fact] void should_not_forward_the_request() => _nextCalled.ShouldBeFalse();
}
