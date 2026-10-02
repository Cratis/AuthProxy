// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.Authentication;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

namespace Cratis.AuthProxy.AccessTokens.for_UserTokenSessions.given;

public class a_cookie_token_session : for_UserAccessTokens.given.user_access_tokens
{
    protected CookieAuthenticationOptions _cookie;
    ServiceProvider _services;

    async Task Establish()
    {
        _config.Session.Lifetime = TimeSpan.FromMinutes(1);
        _config.Session.SlidingExpiration = true;
        _sessionId = await _store.Create(new(Scheme, "refresh-token"), CancellationToken.None);
        var builder = WebApplication.CreateBuilder();
        builder.Configuration.AddInMemoryCollection(new Dictionary<string, string?>
        {
            [$"{C.Session.SectionKey}:Lifetime"] = "00:01:00",
            [$"{C.Session.SectionKey}:SlidingExpiration"] = "true",
        });
        builder.AddIngressAuthentication();
        builder.Services.AddSingleton<IUserTokenStore>(_store);
        _services = builder.Services.BuildServiceProvider();
        _cookie = _services.GetRequiredService<IOptionsMonitor<CookieAuthenticationOptions>>().Get("Cookies");
    }

    protected async Task ValidateCookie()
    {
        var properties = new AuthenticationProperties();
        properties.Items[UserTokenSessions.PropertiesKey] = _sessionId;
        var context = new DefaultHttpContext { RequestServices = _services };
        context.Request.Path = "/frontend";
        await _cookie.Events.ValidatePrincipal(new CookieValidatePrincipalContext(
            context,
            new AuthenticationScheme("Cookies", null, typeof(CookieAuthenticationHandler)),
            _cookie,
            new AuthenticationTicket(new ClaimsPrincipal(new ClaimsIdentity("Cookies")), properties, "Cookies")));
    }

    void Destroy() => _services.Dispose();
}
