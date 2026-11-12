// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.SignInCallbacks;
using Cratis.AuthProxy.SignIns;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

namespace Cratis.AuthProxy.Authentication.for_AuthenticationServiceCollectionExtensions.given;

/// <summary>
/// Provides the real OIDC registrations of one provider that requires a verified e-mail and adds
/// authorization parameters, next to one provider that sets neither.
/// </summary>
public class gated_oidc_providers : Specification
{
    protected OpenIdConnectOptions _strictOptions;
    protected OpenIdConnectOptions _relaxedOptions;
    protected ISignInNotifier _notifier;
    protected IServiceProvider _services;

    void Establish()
    {
        var builder = WebApplication.CreateBuilder();
        const string section = C.Authentication.SectionKey;
        builder.Configuration.AddInMemoryCollection(new Dictionary<string, string?>
        {
            [$"{section}:OidcProviders:0:Name"] = "Strict",
            [$"{section}:OidcProviders:0:Authority"] = "https://login.example.com/tenant",
            [$"{section}:OidcProviders:0:ClientId"] = "strict-client",
            [$"{section}:OidcProviders:0:ClientSecret"] = "strict-secret",
            [$"{section}:OidcProviders:0:RequireVerifiedEmail"] = "true",
            [$"{section}:OidcProviders:0:AuthorizationParameters:connection"] = "email",
            [$"{section}:OidcProviders:0:AuthorizationParameters:prompt"] = "login",
            [$"{section}:OidcProviders:1:Name"] = "Relaxed",
            [$"{section}:OidcProviders:1:Authority"] = "https://login.example.com/other",
            [$"{section}:OidcProviders:1:ClientId"] = "relaxed-client",
            [$"{section}:OidcProviders:1:ClientSecret"] = "relaxed-secret"
        });

        var rootOptions = Substitute.For<IOptionsMonitor<C.AuthProxy>>();
        rootOptions.CurrentValue.Returns(_ => new C.AuthProxy());
        builder.Services.AddSingleton(rootOptions);
        _notifier = Substitute.For<ISignInNotifier>();
        builder.Services.AddSingleton(_notifier);
        builder.Services.AddSingleton(Substitute.For<ISignInCallbackDispatcher>());
        builder.AddIngressConfiguration();
        builder.AddIngressAuthentication();
        _services = builder.Services.BuildServiceProvider();
        var monitor = _services.GetRequiredService<IOptionsMonitor<OpenIdConnectOptions>>();
        _strictOptions = monitor.Get("strict");
        _relaxedOptions = monitor.Get("relaxed");
    }

    protected DefaultHttpContext Context() => new() { RequestServices = _services };

    protected static ClaimsPrincipal PrincipalWith(params (string Type, string Value)[] claims) =>
        new(new ClaimsIdentity(claims.Select(_ => new Claim(_.Type, _.Value)), "AuthenticationTypes.Federation"));

    protected static async Task<TicketReceivedContext> ReceiveTicket(
        DefaultHttpContext context,
        string schemeName,
        OpenIdConnectOptions options,
        ClaimsPrincipal principal)
    {
        var scheme = new AuthenticationScheme(schemeName, schemeName, typeof(OpenIdConnectHandler));
        var ticketContext = new TicketReceivedContext(
            context,
            scheme,
            options,
            new AuthenticationTicket(principal, new AuthenticationProperties(), schemeName));
        await options.Events.OnTicketReceived(ticketContext);
        return ticketContext;
    }
}
