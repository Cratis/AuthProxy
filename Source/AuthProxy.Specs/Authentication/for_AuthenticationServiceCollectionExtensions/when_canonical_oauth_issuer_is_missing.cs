// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

namespace Cratis.AuthProxy.Authentication.for_AuthenticationServiceCollectionExtensions;

public class when_canonical_oauth_issuer_is_missing : Specification
{
    IServiceProvider _services;
    Exception? _exception;

    void Establish()
    {
        var builder = WebApplication.CreateBuilder();
        builder.Configuration.AddInMemoryCollection(new Dictionary<string, string?>
        {
            [$"{C.Authentication.SectionKey}:OAuthProviders:0:Name"] = "GitHub",
            [$"{C.Authentication.SectionKey}:OAuthProviders:0:AuthorizationEndpoint"] = "https://github.example.com/authorize",
            [$"{C.Authentication.SectionKey}:OAuthProviders:0:TokenEndpoint"] = "https://github.example.com/token",
            [$"{C.Authentication.SectionKey}:OAuthProviders:0:UserInformationEndpoint"] = "https://github.example.com/user",
            [$"{C.Authentication.SectionKey}:OAuthProviders:0:ClientId"] = "client-id",
            [$"{C.Authentication.SectionKey}:OAuthProviders:0:CanonicalIdentity:ProviderKey"] = "github-workforce",
            [$"{C.Authentication.SectionKey}:OAuthProviders:0:CanonicalIdentity:SubjectClaimType"] = "id"
        });
        builder.AddIngressConfiguration();
        builder.AddIngressAuthentication();
        _services = builder.Services.BuildServiceProvider();
    }

    void Because() => _exception = Record.Exception(() => _services.GetRequiredService<IOptions<C.Authentication>>().Value);

    [Fact] void should_fail_configuration_validation() => _exception.ShouldBeOfExactType<OptionsValidationException>();
}
