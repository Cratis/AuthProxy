// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.Authentication;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

namespace Cratis.AuthProxy.AccessTokens.for_UserTokenSessions;

public class when_a_provider_cookie_is_active_without_forwarding : for_UserAccessTokens.given.user_access_tokens
{
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task should_follow_the_cookie_retention_instead_of_the_global_sliding_span(bool sliding)
    {
        _config.Session.SlidingExpiration = true;
        var session = new UserTokenSession(Scheme, "refresh-token")
        {
            ExpiresAt = sliding ? null : _time.GetUtcNow().AddMinutes(1),
            Lifetime = TimeSpan.FromMinutes(1),
            Sliding = sliding
        };
        _sessionId = await _store.Create(session, CancellationToken.None);
        var builder = WebApplication.CreateBuilder();
        builder.Configuration.AddInMemoryCollection(new Dictionary<string, string?> { [$"{C.Session.SectionKey}:SlidingExpiration"] = "true" });
        builder.AddIngressAuthentication();
        builder.Services.AddSingleton<IUserTokenStore>(_store);
        await using var services = builder.Services.BuildServiceProvider();
        var cookie = services.GetRequiredService<IOptionsMonitor<CookieAuthenticationOptions>>().Get("Cookies");
        for (var request = 0; request < 3; request++)
        {
            _time.Advance(TimeSpan.FromSeconds(40));
            var properties = new AuthenticationProperties { AllowRefresh = sliding };
            properties.Items[UserTokenSessions.PropertiesKey] = _sessionId;
            var context = new DefaultHttpContext { RequestServices = services };
            context.Request.Path = "/frontend";
            await cookie.Events.ValidatePrincipal(new CookieValidatePrincipalContext(
                context,
                new AuthenticationScheme("Cookies", null, typeof(CookieAuthenticationHandler)),
                cookie,
                new AuthenticationTicket(new ClaimsPrincipal(new ClaimsIdentity("Cookies")), properties, "Cookies")));
        }
        _endpoint.Received.ShouldBeEmpty();
        var result = await Get();
        if (sliding) result.Token.ShouldEqual("access-token");
        else result.Token.ShouldBeNull();
        _time.Advance(TimeSpan.FromMinutes(1));
        (await _store.Get(_sessionId, CancellationToken.None)).ShouldBeNull();
    }
}
