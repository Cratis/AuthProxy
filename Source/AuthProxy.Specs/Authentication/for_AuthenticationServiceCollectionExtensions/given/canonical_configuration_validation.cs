// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

namespace Cratis.AuthProxy.Authentication.for_AuthenticationServiceCollectionExtensions.given;

/// <summary>
/// Provides the real authentication options registration and validation path for canonical identity configuration specs.
/// </summary>
public class canonical_configuration_validation : Specification
{
    /// <summary>
    /// Builds a complete valid OIDC provider configuration.
    /// </summary>
    /// <param name="index">The provider list index.</param>
    /// <param name="name">The provider display name.</param>
    /// <param name="providerKey">The canonical provider key.</param>
    /// <param name="subjectClaimType">The canonical subject claim type.</param>
    /// <param name="issuer">The optional literal canonical issuer.</param>
    /// <returns>The provider configuration entries.</returns>
    protected static Dictionary<string, string?> ValidOidcProvider(
        int index = 0,
        string name = "Workforce",
        string providerKey = "workforce",
        string subjectClaimType = "oid",
        string? issuer = null)
    {
        var prefix = $"{C.Authentication.SectionKey}:OidcProviders:{index}";
        var configuration = new Dictionary<string, string?>
        {
            [$"{prefix}:Name"] = name,
            [$"{prefix}:Authority"] = "https://identity.example.com",
            [$"{prefix}:ClientId"] = "client-id",
            [$"{prefix}:CanonicalIdentity:ProviderKey"] = providerKey,
            [$"{prefix}:CanonicalIdentity:SubjectClaimType"] = subjectClaimType
        };

        if (issuer is not null)
        {
            configuration[$"{prefix}:CanonicalIdentity:Issuer"] = issuer;
        }

        return configuration;
    }

    /// <summary>
    /// Builds a complete valid OAuth provider configuration.
    /// </summary>
    /// <param name="index">The provider list index.</param>
    /// <param name="name">The provider display name.</param>
    /// <param name="providerKey">The canonical provider key.</param>
    /// <param name="subjectClaimType">The canonical subject claim type.</param>
    /// <param name="issuer">The literal canonical issuer.</param>
    /// <returns>The provider configuration entries.</returns>
    protected static Dictionary<string, string?> ValidOAuthProvider(
        int index = 0,
        string name = "GitHub",
        string providerKey = "github-workforce",
        string subjectClaimType = "id",
        string issuer = "https://github.example.com")
    {
        var prefix = $"{C.Authentication.SectionKey}:OAuthProviders:{index}";
        return new Dictionary<string, string?>
        {
            [$"{prefix}:Name"] = name,
            [$"{prefix}:AuthorizationEndpoint"] = "https://github.example.com/authorize",
            [$"{prefix}:TokenEndpoint"] = "https://github.example.com/token",
            [$"{prefix}:UserInformationEndpoint"] = "https://github.example.com/user",
            [$"{prefix}:ClientId"] = "client-id",
            [$"{prefix}:CanonicalIdentity:ProviderKey"] = providerKey,
            [$"{prefix}:CanonicalIdentity:SubjectClaimType"] = subjectClaimType,
            [$"{prefix}:CanonicalIdentity:Issuer"] = issuer
        };
    }

    /// <summary>
    /// Combines provider configuration entries into one configuration source.
    /// </summary>
    /// <param name="providers">The provider configuration entry sets.</param>
    /// <returns>The combined configuration entries.</returns>
    protected static Dictionary<string, string?> Configuration(params Dictionary<string, string?>[] providers) =>
        providers.SelectMany(_ => _).ToDictionary(_ => _.Key, _ => _.Value);

    /// <summary>
    /// Builds a service provider through the public ingress registration path.
    /// </summary>
    /// <param name="configuration">The authentication configuration entries.</param>
    /// <returns>The configured service provider.</returns>
    protected static IServiceProvider BuildServices(Dictionary<string, string?> configuration)
    {
        var builder = WebApplication.CreateBuilder();
        builder.Configuration.AddInMemoryCollection(configuration);
        builder.AddIngressConfiguration();
        builder.AddIngressAuthentication();
        return builder.Services.BuildServiceProvider();
    }

    /// <summary>
    /// Resolves authentication options so every registered options validator runs.
    /// </summary>
    /// <param name="services">The configured service provider.</param>
    /// <returns>The exception raised by options validation, or <see langword="null"/> when validation succeeds.</returns>
    protected static Exception? ResolveAuthenticationOptions(IServiceProvider services) =>
        Record.Exception(() => services.GetRequiredService<IOptions<C.Authentication>>().Value);
}
