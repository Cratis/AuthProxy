// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.SignInCallbacks;
using Cratis.AuthProxy.SignIns;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.OAuth;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

namespace Cratis.AuthProxy.Authentication.for_AuthenticationServiceCollectionExtensions.given;

public class configured_provider_sessions : Specification
{
    protected readonly for_SessionLifetimePolicy.given.a_session_clock _clock = new();

    protected ServiceProvider Services(string? lifetime, bool? providerSliding, bool globalSliding = false)
    {
        var builder = WebApplication.CreateBuilder();
        var values = new Dictionary<string, string?>
        {
            [$"{C.Session.SectionKey}:SlidingExpiration"] = globalSliding.ToString(),
            [$"{C.Authentication.SectionKey}:OidcProviders:0:Name"] = "work",
            [$"{C.Authentication.SectionKey}:OidcProviders:0:Authority"] = "https://id.example.com",
            [$"{C.Authentication.SectionKey}:OidcProviders:0:ClientId"] = "client",
            [$"{C.Authentication.SectionKey}:OAuthProviders:0:Name"] = "social",
            [$"{C.Authentication.SectionKey}:OAuthProviders:0:ClientId"] = "client",
            [$"{C.Authentication.SectionKey}:OAuthProviders:0:ClientSecret"] = "spec-client-secret",
            [$"{C.Authentication.SectionKey}:OAuthProviders:0:AuthorizationEndpoint"] = "https://social.example.com/authorize",
            [$"{C.Authentication.SectionKey}:OAuthProviders:0:TokenEndpoint"] = "https://social.example.com/token",
            [$"{C.Authentication.SectionKey}:OAuthProviders:0:UserInformationEndpoint"] = "https://social.example.com/user"
        };
        foreach (var kind in new[] { "OidcProviders", "OAuthProviders" })
        {
            if (lifetime is not null) values[$"{C.Authentication.SectionKey}:{kind}:0:Session:Lifetime"] = lifetime;
            if (providerSliding is not null) values[$"{C.Authentication.SectionKey}:{kind}:0:Session:SlidingExpiration"] = providerSliding.ToString();
        }
        builder.Configuration.AddInMemoryCollection(values);
        builder.AddIngressConfiguration();
        builder.AddIngressAuthentication();
        builder.Services.AddSingleton<TimeProvider>(_clock);
        builder.Services.AddSingleton(Substitute.For<ISignInNotifier>());
        builder.Services.AddSingleton(Substitute.For<ISignInCallbackDispatcher>());
        return builder.Services.BuildServiceProvider();
    }

    protected static TicketReceivedContext Ticket(ServiceProvider services, bool oidc, AuthenticationProperties properties)
    {
        var scheme = oidc ? "work" : "social";
        RemoteAuthenticationOptions options = oidc
            ? services.GetRequiredService<IOptionsMonitor<OpenIdConnectOptions>>().Get(scheme)
            : services.GetRequiredService<IOptionsMonitor<OAuthOptions>>().Get(scheme);
        var principal = new ClaimsPrincipal(new ClaimsIdentity([new Claim(ClaimTypes.NameIdentifier, "subject"), new Claim("Session:Lifetime", "24:00:00"), new Claim("Session:SlidingExpiration", "true")], scheme));
        var context = new DefaultHttpContext { RequestServices = services };
        context.Request.QueryString = new QueryString("?Session:Lifetime=24:00:00&Session:SlidingExpiration=true");
        return new TicketReceivedContext(context, new AuthenticationScheme(scheme, scheme, typeof(OpenIdConnectHandler)), options, new AuthenticationTicket(principal, properties, scheme));
    }

    protected static Task Receive(TicketReceivedContext context) => context.Options switch
    {
        OpenIdConnectOptions oidc => oidc.Events.OnTicketReceived(context),
        OAuthOptions oauth => oauth.Events.OnTicketReceived(context),
        _ => throw new InvalidOperationException()
    };
}
