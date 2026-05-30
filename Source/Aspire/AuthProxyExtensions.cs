// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Aspire;

/// <summary>
/// Extension methods for adding and configuring <see cref="AuthProxyResource"/> in an Aspire application model.
/// </summary>
public static class AuthProxyExtensions
{
    const string ConfigPrefix = "Cratis__AuthProxy";

    /// <summary>
    /// Adds an AuthProxy container resource to the application model.
    /// </summary>
    /// <param name="builder">The <see cref="IDistributedApplicationBuilder"/>.</param>
    /// <param name="name">The resource name (e.g. <c>"authproxy"</c>).</param>
    /// <param name="tag">
    /// Optional Docker image tag.  Defaults to <see cref="AuthProxyResource.ContainerImageTag"/> (<c>latest</c>).
    /// Pin this to a specific release in production (e.g. <c>"1.2.3"</c>).
    /// </param>
    /// <returns>An <see cref="IResourceBuilder{T}"/> for the <see cref="AuthProxyResource"/>.</returns>
    public static IResourceBuilder<AuthProxyResource> AddAuthProxy(
        this IDistributedApplicationBuilder builder,
        string name,
        string? tag = null) =>
        builder
            .AddResource(new AuthProxyResource(name))
            .WithImage(AuthProxyResource.ContainerImageName, tag ?? AuthProxyResource.ContainerImageTag);

    /// <summary>
    /// Registers a backend (API) endpoint for a named service in AuthProxy.
    /// </summary>
    /// <typeparam name="T">The resource type (must support environment variables).</typeparam>
    /// <param name="builder">The resource builder.</param>
    /// <param name="serviceName">
    /// The service key used in the AuthProxy <c>Services</c> configuration (e.g. <c>"main"</c>).
    /// </param>
    /// <param name="serviceResource">The Aspire resource that exposes the backend.</param>
    /// <param name="endpointName">The endpoint name to use.  Defaults to <c>"http"</c>.</param>
    /// <returns>The same <see cref="IResourceBuilder{T}"/> for chaining.</returns>
    public static IResourceBuilder<T> WithBackend<T>(
        this IResourceBuilder<T> builder,
        string serviceName,
        IResourceBuilder<IResourceWithEndpoints> serviceResource,
        string endpointName = "http")
        where T : IResourceWithEnvironment
    {
        var endpoint = serviceResource.GetEndpoint(endpointName);
        return builder.WithEnvironment(context =>
            context.EnvironmentVariables[$"{ConfigPrefix}__Services__{serviceName}__Backend__BaseUrl"] =
                ReferenceExpression.Create($"{endpoint}/"));
    }

    /// <summary>
    /// Registers a frontend (SPA / static-assets) endpoint for a named service in AuthProxy.
    /// </summary>
    /// <typeparam name="T">The resource type (must support environment variables).</typeparam>
    /// <param name="builder">The resource builder.</param>
    /// <param name="serviceName">
    /// The service key used in the AuthProxy <c>Services</c> configuration (e.g. <c>"main"</c>).
    /// </param>
    /// <param name="serviceResource">The Aspire resource that exposes the frontend.</param>
    /// <param name="endpointName">The endpoint name to use.  Defaults to <c>"http"</c>.</param>
    /// <returns>The same <see cref="IResourceBuilder{T}"/> for chaining.</returns>
    public static IResourceBuilder<T> WithFrontend<T>(
        this IResourceBuilder<T> builder,
        string serviceName,
        IResourceBuilder<IResourceWithEndpoints> serviceResource,
        string endpointName = "http")
        where T : IResourceWithEnvironment
    {
        var endpoint = serviceResource.GetEndpoint(endpointName);
        return builder.WithEnvironment(context =>
            context.EnvironmentVariables[$"{ConfigPrefix}__Services__{serviceName}__Frontend__BaseUrl"] =
                ReferenceExpression.Create($"{endpoint}/"));
    }

    /// <summary>
    /// Adds an OIDC provider to the AuthProxy authentication configuration.
    /// </summary>
    /// <typeparam name="T">The resource type (must support environment variables).</typeparam>
    /// <param name="builder">The resource builder.</param>
    /// <param name="name">The display name shown on the login page (e.g. <c>"Contoso AD"</c>).</param>
    /// <param name="type">The provider brand / type.  Used by the login UI to choose the correct logo.</param>
    /// <param name="authority">The OIDC authority / issuer URL.</param>
    /// <param name="clientId">The OAuth client ID.</param>
    /// <param name="clientSecret">The OAuth client secret.</param>
    /// <param name="scopes">
    /// Optional extra OAuth scopes to request in addition to <c>openid profile email</c>.
    /// </param>
    /// <returns>The same <see cref="IResourceBuilder{T}"/> for chaining.</returns>
    public static IResourceBuilder<T> WithOidcProvider<T>(
        this IResourceBuilder<T> builder,
        string name,
        OidcProviderType type,
        string authority,
        string clientId,
        string clientSecret,
        IEnumerable<string>? scopes = null)
        where T : IResourceWithEnvironment
    {
        var annotation = GetOrCreateAnnotation(builder.Resource);
        var idx = annotation.OidcProviderCount++;
        var prefix = $"{ConfigPrefix}__Authentication__OidcProviders__{idx}";

        builder
            .WithEnvironment($"{prefix}__Name", name)
            .WithEnvironment($"{prefix}__Type", type.ToString())
            .WithEnvironment($"{prefix}__Authority", authority)
            .WithEnvironment($"{prefix}__ClientId", clientId)
            .WithEnvironment($"{prefix}__ClientSecret", clientSecret);

        var scopeList = scopes?.ToList() ?? [];
        for (var i = 0; i < scopeList.Count; i++)
        {
            builder.WithEnvironment($"{prefix}__Scopes__{i}", scopeList[i]);
        }

        return builder;
    }

    /// <summary>
    /// Adds a regular OAuth 2.0 (non-OIDC) provider such as GitHub to the AuthProxy authentication configuration.
    /// </summary>
    /// <typeparam name="T">The resource type (must support environment variables).</typeparam>
    /// <param name="builder">The resource builder.</param>
    /// <param name="name">The display name shown on the login page (e.g. <c>"GitHub"</c>).</param>
    /// <param name="type">The provider brand / type.</param>
    /// <param name="authorizationEndpoint">The OAuth 2.0 authorization endpoint URL.</param>
    /// <param name="tokenEndpoint">The OAuth 2.0 token endpoint URL.</param>
    /// <param name="userInformationEndpoint">The user-information (profile) API endpoint URL.</param>
    /// <param name="clientId">The OAuth client ID.</param>
    /// <param name="clientSecret">The OAuth client secret.</param>
    /// <param name="scopes">Optional extra OAuth scopes to request.</param>
    /// <param name="claimMappings">
    /// Optional claim mappings from the user-info JSON response.
    /// Key = claim type; value = JSON field name in the user-info response.
    /// </param>
    /// <returns>The same <see cref="IResourceBuilder{T}"/> for chaining.</returns>
    public static IResourceBuilder<T> WithOAuthProvider<T>(
        this IResourceBuilder<T> builder,
        string name,
        OidcProviderType type,
        string authorizationEndpoint,
        string tokenEndpoint,
        string userInformationEndpoint,
        string clientId,
        string clientSecret,
        IEnumerable<string>? scopes = null,
        IDictionary<string, string>? claimMappings = null)
        where T : IResourceWithEnvironment
    {
        var annotation = GetOrCreateAnnotation(builder.Resource);
        var idx = annotation.OAuthProviderCount++;
        var prefix = $"{ConfigPrefix}__Authentication__OAuthProviders__{idx}";

        builder
            .WithEnvironment($"{prefix}__Name", name)
            .WithEnvironment($"{prefix}__Type", type.ToString())
            .WithEnvironment($"{prefix}__AuthorizationEndpoint", authorizationEndpoint)
            .WithEnvironment($"{prefix}__TokenEndpoint", tokenEndpoint)
            .WithEnvironment($"{prefix}__UserInformationEndpoint", userInformationEndpoint)
            .WithEnvironment($"{prefix}__ClientId", clientId)
            .WithEnvironment($"{prefix}__ClientSecret", clientSecret);

        var scopeList = scopes?.ToList() ?? [];
        for (var i = 0; i < scopeList.Count; i++)
        {
            builder.WithEnvironment($"{prefix}__Scopes__{i}", scopeList[i]);
        }

        if (claimMappings is not null)
        {
            foreach (var (claimType, jsonField) in claimMappings)
            {
                builder.WithEnvironment($"{prefix}__ClaimMappings__{claimType}", jsonField);
            }
        }

        return builder;
    }

    /// <summary>
    /// Adds a host-name-based tenant resolution strategy to AuthProxy.
    /// The resolved host is matched against the <c>Domains</c> list of each configured tenant.
    /// </summary>
    /// <typeparam name="T">The resource type (must support environment variables).</typeparam>
    /// <param name="builder">The resource builder.</param>
    /// <returns>The same <see cref="IResourceBuilder{T}"/> for chaining.</returns>
    public static IResourceBuilder<T> WithHostTenantResolution<T>(this IResourceBuilder<T> builder)
        where T : IResourceWithEnvironment =>
        AddTenantResolution(builder, "Host");

    /// <summary>
    /// Adds a sub-host-based tenant resolution strategy to AuthProxy.
    /// The tenant ID is derived from the first subdomain label of the request host by convention
    /// (e.g. <c>acme.example.com</c> → <c>acme</c>).
    /// </summary>
    /// <typeparam name="T">The resource type (must support environment variables).</typeparam>
    /// <param name="builder">The resource builder.</param>
    /// <returns>The same <see cref="IResourceBuilder{T}"/> for chaining.</returns>
    public static IResourceBuilder<T> WithSubHostTenantResolution<T>(this IResourceBuilder<T> builder)
        where T : IResourceWithEnvironment =>
        AddTenantResolution(builder, "SubHost");

    /// <summary>
    /// Adds a claim-based tenant resolution strategy to AuthProxy.
    /// The tenant source identifier is read from the specified claim in the authenticated principal.
    /// </summary>
    /// <typeparam name="T">The resource type (must support environment variables).</typeparam>
    /// <param name="builder">The resource builder.</param>
    /// <param name="claimType">
    /// The claim type to read.
    /// When <see langword="null"/> the AuthProxy default (the Microsoft standard tenant claim) is used.
    /// </param>
    /// <returns>The same <see cref="IResourceBuilder{T}"/> for chaining.</returns>
    public static IResourceBuilder<T> WithClaimTenantResolution<T>(
        this IResourceBuilder<T> builder,
        string? claimType = null)
        where T : IResourceWithEnvironment
    {
        var annotation = GetOrCreateAnnotation(builder.Resource);
        var idx = annotation.TenantResolutionCount++;
        var prefix = $"{ConfigPrefix}__TenantResolutions__{idx}";

        builder.WithEnvironment($"{prefix}__Strategy", "Claim");
        if (!string.IsNullOrEmpty(claimType))
        {
            builder.WithEnvironment($"{prefix}__Options__ClaimType", claimType);
        }

        return builder;
    }

    /// <summary>
    /// Adds a route-segment-based tenant resolution strategy to AuthProxy.
    /// The tenant source identifier is extracted from the request path using a named-group regular expression.
    /// </summary>
    /// <typeparam name="T">The resource type (must support environment variables).</typeparam>
    /// <param name="builder">The resource builder.</param>
    /// <param name="pattern">
    /// A regular expression with a named capture group whose value becomes the tenant source identifier.
    /// Example: <c>^/(?&lt;tenant&gt;[^/]+)/</c>.
    /// </param>
    /// <returns>The same <see cref="IResourceBuilder{T}"/> for chaining.</returns>
    public static IResourceBuilder<T> WithRouteTenantResolution<T>(
        this IResourceBuilder<T> builder,
        string pattern)
        where T : IResourceWithEnvironment
    {
        var annotation = GetOrCreateAnnotation(builder.Resource);
        var idx = annotation.TenantResolutionCount++;
        var prefix = $"{ConfigPrefix}__TenantResolutions__{idx}";

        return builder
            .WithEnvironment($"{prefix}__Strategy", "Route")
            .WithEnvironment($"{prefix}__Options__Pattern", pattern);
    }

    /// <summary>
    /// Adds a fixed-tenant resolution strategy to AuthProxy.
    /// Every request is resolved to the same pre-configured tenant ID (single-tenant deployments).
    /// </summary>
    /// <typeparam name="T">The resource type (must support environment variables).</typeparam>
    /// <param name="builder">The resource builder.</param>
    /// <param name="tenantId">The tenant ID that every request should resolve to.</param>
    /// <returns>The same <see cref="IResourceBuilder{T}"/> for chaining.</returns>
    public static IResourceBuilder<T> WithSpecifiedTenantResolution<T>(
        this IResourceBuilder<T> builder,
        string tenantId)
        where T : IResourceWithEnvironment
    {
        var annotation = GetOrCreateAnnotation(builder.Resource);
        var idx = annotation.TenantResolutionCount++;
        var prefix = $"{ConfigPrefix}__TenantResolutions__{idx}";

        return builder
            .WithEnvironment($"{prefix}__Strategy", "Specified")
            .WithEnvironment($"{prefix}__Options__TenantId", tenantId);
    }

    /// <summary>
    /// Adds a default-tenant fallback resolution strategy to AuthProxy.
    /// Resolves to the configured default tenant ID when no other strategy matches.
    /// </summary>
    /// <typeparam name="T">The resource type (must support environment variables).</typeparam>
    /// <param name="builder">The resource builder.</param>
    /// <param name="tenantId">The fallback tenant ID.</param>
    /// <returns>The same <see cref="IResourceBuilder{T}"/> for chaining.</returns>
    public static IResourceBuilder<T> WithDefaultTenantResolution<T>(
        this IResourceBuilder<T> builder,
        string tenantId)
        where T : IResourceWithEnvironment
    {
        var annotation = GetOrCreateAnnotation(builder.Resource);
        var idx = annotation.TenantResolutionCount++;
        var prefix = $"{ConfigPrefix}__TenantResolutions__{idx}";

        return builder
            .WithEnvironment($"{prefix}__Strategy", "Default")
            .WithEnvironment($"{prefix}__Options__TenantId", tenantId);
    }

    /// <summary>
    /// Adds a cookie-selection-based tenant resolution strategy to AuthProxy.
    /// The tenant ID is read from the cookie set by the AuthProxy tenant-selection page.
    /// </summary>
    /// <typeparam name="T">The resource type (must support environment variables).</typeparam>
    /// <param name="builder">The resource builder.</param>
    /// <returns>The same <see cref="IResourceBuilder{T}"/> for chaining.</returns>
    public static IResourceBuilder<T> WithSelectionTenantResolution<T>(this IResourceBuilder<T> builder)
        where T : IResourceWithEnvironment =>
        AddTenantResolution(builder, "Selection");

    /// <summary>
    /// Configures AuthProxy to verify that a resolved tenant actually exists by calling an external HTTP endpoint.
    /// </summary>
    /// <typeparam name="T">The resource type (must support environment variables).</typeparam>
    /// <param name="builder">The resource builder.</param>
    /// <param name="urlTemplate">
    /// A URL template used to check whether a tenant exists.
    /// Use <c>{tenantId}</c> as a placeholder for the resolved tenant identifier,
    /// e.g. <c>https://platform.example.com/api/tenants/{tenantId}</c>.
    /// An HTTP GET to the resolved URL must return <c>200</c> when the tenant exists and <c>404</c> when it does not.
    /// </param>
    /// <returns>The same <see cref="IResourceBuilder{T}"/> for chaining.</returns>
    public static IResourceBuilder<T> WithTenantVerification<T>(
        this IResourceBuilder<T> builder,
        string urlTemplate)
        where T : IResourceWithEnvironment =>
        builder.WithEnvironment($"{ConfigPrefix}__TenantVerification__UrlTemplate", urlTemplate);

    static IResourceBuilder<T> AddTenantResolution<T>(IResourceBuilder<T> builder, string strategy)
        where T : IResourceWithEnvironment
    {
        var annotation = GetOrCreateAnnotation(builder.Resource);
        var idx = annotation.TenantResolutionCount++;
        return builder.WithEnvironment($"{ConfigPrefix}__TenantResolutions__{idx}__Strategy", strategy);
    }

    static AuthProxyConfigAnnotation GetOrCreateAnnotation(IResource resource)
    {
        if (resource.TryGetLastAnnotation<AuthProxyConfigAnnotation>(out var annotation))
        {
            return annotation;
        }

        var newAnnotation = new AuthProxyConfigAnnotation();
        resource.Annotations.Add(newAnnotation);
        return newAnnotation;
    }
}
