// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

namespace Cratis.AuthProxy.Authentication.for_AuthenticationServiceCollectionExtensions;

public class when_registering_user_token_capture : Specification
{
    OpenIdConnectOptions _oidc;
    CookieAuthenticationOptions _cookie;

    void Establish()
    {
        var builder = WebApplication.CreateBuilder();
        builder.Configuration.AddInMemoryCollection(new Dictionary<string, string?>
        {
            [$"{C.Authentication.SectionKey}:OidcProviders:0:Name"] = "Workforce",
            [$"{C.Authentication.SectionKey}:OidcProviders:0:Authority"] = "https://login.microsoftonline.com/tenant/v2.0",
            [$"{C.Authentication.SectionKey}:OidcProviders:0:ClientId"] = "client-id",
            [$"{C.Authentication.SectionKey}:OidcProviders:0:ClientSecret"] = "client-secret",
        });

        builder.AddIngressAuthentication();
        var services = builder.Services.BuildServiceProvider();
        _oidc = services.GetRequiredService<IOptionsMonitor<OpenIdConnectOptions>>().Get("workforce");
        _cookie = services.GetRequiredService<IOptionsMonitor<CookieAuthenticationOptions>>().Get(CookieAuthenticationDefaults.AuthenticationScheme);
    }

    [Fact] void should_capture_the_token_response() => _oidc.Events.OnTokenResponseReceived.ShouldNotBeNull();
    [Fact] void should_not_save_tokens_in_the_session_cookie() => _oidc.SaveTokens.ShouldBeFalse();
    [Fact] void should_forget_token_sessions_on_sign_out() => _cookie.Events.OnSigningOut.ShouldNotBeNull();
}
