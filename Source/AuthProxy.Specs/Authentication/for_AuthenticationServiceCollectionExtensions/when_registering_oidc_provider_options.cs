// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

namespace Cratis.AuthProxy.Authentication.for_AuthenticationServiceCollectionExtensions;

public class when_registering_oidc_provider_options : Specification
{
    OpenIdConnectOptions _options;

    void Establish()
    {
        var builder = WebApplication.CreateBuilder();
        builder.Configuration.AddInMemoryCollection(new Dictionary<string, string?>
        {
            [$"{C.Authentication.SectionKey}:OidcProviders:0:Name"] = "Microsoft",
            [$"{C.Authentication.SectionKey}:OidcProviders:0:Authority"] = "https://login.microsoftonline.com/common/v2.0",
            [$"{C.Authentication.SectionKey}:OidcProviders:0:ClientId"] = "client-id",
            [$"{C.Authentication.SectionKey}:OidcProviders:0:ClientSecret"] = "client-secret",
            [$"{C.Authentication.SectionKey}:OidcProviders:0:Scopes:0"] = "offline_access"
        });

        builder.AddIngressAuthentication();

        var serviceProvider = builder.Services.BuildServiceProvider();
        var monitor = serviceProvider.GetRequiredService<IOptionsMonitor<OpenIdConnectOptions>>();
        _options = monitor.Get("microsoft");
    }

    [Fact] void should_set_authority() => _options.Authority.ShouldEqual("https://login.microsoftonline.com/common/v2.0");
    [Fact] void should_set_client_credentials() => _options.ClientId.ShouldEqual("client-id");
    [Fact] void should_set_callback_path() => _options.CallbackPath.ToString().ShouldEqual("/signin-microsoft");
    [Fact] void should_include_standard_scopes() => _options.Scope.Contains("openid").ShouldBeTrue();
    [Fact] void should_include_custom_scopes() => _options.Scope.Contains("offline_access").ShouldBeTrue();
    [Fact] void should_configure_ticket_received_event() => _options.Events.OnTicketReceived.ShouldNotBeNull();
}
