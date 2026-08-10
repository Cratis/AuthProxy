// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

namespace Cratis.AuthProxy.Authentication.for_AuthenticationServiceCollectionExtensions;

/// <summary>
/// Specifies that canonical subject selection cannot consume any case-varied claim in AuthProxy's reserved namespace.
/// </summary>
public class when_canonical_subject_claim_uses_the_reserved_namespace : Specification
{
    IServiceProvider _services;
    Exception? _exception;

    void Establish()
    {
        var builder = WebApplication.CreateBuilder();
        builder.Configuration.AddInMemoryCollection(new Dictionary<string, string?>
        {
            [$"{C.Authentication.SectionKey}:OidcProviders:0:Name"] = "Workforce",
            [$"{C.Authentication.SectionKey}:OidcProviders:0:Authority"] = "https://identity.example.com",
            [$"{C.Authentication.SectionKey}:OidcProviders:0:ClientId"] = "client-id",
            [$"{C.Authentication.SectionKey}:OidcProviders:0:CanonicalIdentity:ProviderKey"] = "workforce",
            [$"{C.Authentication.SectionKey}:OidcProviders:0:CanonicalIdentity:SubjectClaimType"] = "URN:CRATIS:IDENTITY:unexpected"
        });
        builder.AddIngressConfiguration();
        builder.AddIngressAuthentication();
        _services = builder.Services.BuildServiceProvider();
    }

    void Because() => _exception = Record.Exception(() => _services.GetRequiredService<IOptions<C.Authentication>>().Value);

    [Fact] void should_fail_configuration_validation() => _exception.ShouldBeOfExactType<OptionsValidationException>();
}
