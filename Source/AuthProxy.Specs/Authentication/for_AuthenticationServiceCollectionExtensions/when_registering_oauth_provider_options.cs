// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.AspNetCore.Authentication.OAuth;
using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

namespace Cratis.AuthProxy.Authentication.for_AuthenticationServiceCollectionExtensions;

public class when_registering_oauth_provider_options : Specification
{
    OAuthOptions _options;

    void Establish()
    {
        var builder = WebApplication.CreateBuilder();
        builder.Configuration.AddInMemoryCollection(new Dictionary<string, string?>
        {
            [$"{C.Authentication.SectionKey}:OAuthProviders:0:Name"] = "GitHub",
            [$"{C.Authentication.SectionKey}:OAuthProviders:0:AuthorizationEndpoint"] = "https://github.com/login/oauth/authorize",
            [$"{C.Authentication.SectionKey}:OAuthProviders:0:TokenEndpoint"] = "https://github.com/login/oauth/access_token",
            [$"{C.Authentication.SectionKey}:OAuthProviders:0:UserInformationEndpoint"] = "https://api.github.com/user",
            [$"{C.Authentication.SectionKey}:OAuthProviders:0:ClientId"] = "client-id",
            [$"{C.Authentication.SectionKey}:OAuthProviders:0:ClientSecret"] = "client-secret",
            [$"{C.Authentication.SectionKey}:OAuthProviders:0:Scopes:0"] = "read:user",
            [$"{C.Authentication.SectionKey}:OAuthProviders:0:ClaimMappings:0:Key"] = "sub",
            [$"{C.Authentication.SectionKey}:OAuthProviders:0:ClaimMappings:0:Value"] = "id"
        });

        builder.AddIngressAuthentication();

        var serviceProvider = builder.Services.BuildServiceProvider();
        var monitor = serviceProvider.GetRequiredService<IOptionsMonitor<OAuthOptions>>();
        _options = monitor.Get("github");
    }

    [Fact] void should_set_oauth_endpoints() => _options.AuthorizationEndpoint.ShouldEqual("https://github.com/login/oauth/authorize");
    [Fact] void should_set_callback_path() => _options.CallbackPath.ToString().ShouldEqual("/signin-github");
    [Fact] void should_include_configured_scope() => _options.Scope.Contains("read:user").ShouldBeTrue();
    [Fact] void should_register_ticket_creation_event() => _options.Events.OnCreatingTicket.ShouldNotBeNull();
    [Fact] void should_register_ticket_received_event() => _options.Events.OnTicketReceived.ShouldNotBeNull();
}
