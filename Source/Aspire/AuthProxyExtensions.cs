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
    /// <param name="resolveIdentityDetails">
    /// Whether AuthProxy should call <c>GET {baseUrl}/.cratis/me</c> on this backend to enrich
    /// the identity cookie after authentication.  Defaults to <see langword="null"/> (AuthProxy uses
    /// its own default — <see langword="true"/> when a backend URL is present).
    /// Set to <see langword="false"/> explicitly to opt this service out of identity enrichment.
    /// </param>
    /// <returns>The same <see cref="IResourceBuilder{T}"/> for chaining.</returns>
    public static IResourceBuilder<T> WithBackend<T>(
        this IResourceBuilder<T> builder,
        string serviceName,
        IResourceBuilder<IResourceWithEndpoints> serviceResource,
        string endpointName = "http",
        bool? resolveIdentityDetails = null)
        where T : IResourceWithEnvironment
    {
        var endpoint = serviceResource.GetEndpoint(endpointName);
        builder.WithEnvironment(context =>
            context.EnvironmentVariables[$"{ConfigPrefix}__Services__{serviceName}__Backend__BaseUrl"] =
                ReferenceExpression.Create($"{endpoint}/"));

        if (resolveIdentityDetails.HasValue)
        {
            builder.WithEnvironment(
                $"{ConfigPrefix}__Services__{serviceName}__ResolveIdentityDetails",
                resolveIdentityDetails.Value.ToString());
        }

        return builder;
    }

    /// <summary>
    /// Declares what a named service's <c>/.cratis/me</c> answer means to AuthProxy.
    /// </summary>
    /// <typeparam name="T">The resource type (must support environment variables).</typeparam>
    /// <param name="builder">The resource builder.</param>
    /// <param name="serviceName">
    /// The service key used in the AuthProxy <c>Services</c> configuration (e.g. <c>"main"</c>).
    /// </param>
    /// <param name="mode">
    /// What the answer is worth. <see cref="IdentityVerificationMode.BestEffort"/> — the default when this
    /// is never called — treats the endpoint as enrichment, so only an explicit <c>403</c> denies.
    /// <see cref="IdentityVerificationMode.Required"/> treats it as an authorization decision, so only an
    /// explicit positive admits and every failure to obtain one denies.
    /// </param>
    /// <param name="timeout">
    /// How long to wait for the answer. Defaults to <see langword="null"/> (AuthProxy's own default of ten
    /// seconds). Pass a non-positive value to leave the wait unbounded.
    /// </param>
    /// <returns>The same <see cref="IResourceBuilder{T}"/> for chaining.</returns>
    /// <remarks>
    /// Deliberately its own method rather than another optional parameter on
    /// <see cref="WithBackend{T}(IResourceBuilder{T}, string, IResourceBuilder{IResourceWithEndpoints}, string, bool?)"/>.
    /// An optional argument is baked into the call site when the app host is compiled, so adding one changes
    /// the method's signature and every already-built app host would fail to bind against the new package
    /// until it is rebuilt.
    /// <para>
    /// This is orthogonal to <c>resolveIdentityDetails</c> on <c>WithBackend</c>, which decides whether the
    /// endpoint is called at all. Opting a service out of identity resolution and then requiring
    /// verification of it asks for a decision from a service that is never consulted, so the service simply
    /// does not take part.
    /// </para>
    /// <para>
    /// Requiring verification means an outage of that service refuses every proxied request rather than
    /// serving callers whose access nobody could confirm. That is the point of the setting, and it is worth
    /// stating plainly before turning it on.
    /// </para>
    /// </remarks>
    public static IResourceBuilder<T> WithIdentityVerification<T>(
        this IResourceBuilder<T> builder,
        string serviceName,
        IdentityVerificationMode mode,
        TimeSpan? timeout = null)
        where T : IResourceWithEnvironment
    {
        builder.WithEnvironment(
            $"{ConfigPrefix}__Services__{serviceName}__IdentityVerification",
            mode.ToString());

        if (timeout.HasValue)
        {
            builder.WithEnvironment(
                $"{ConfigPrefix}__Services__{serviceName}__IdentityVerificationTimeout",
                timeout.Value.ToString("c", CultureInfo.InvariantCulture));
        }

        return builder;
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
    /// Declares the request paths on a named service that are served to unauthenticated callers.
    /// </summary>
    /// <typeparam name="T">The resource type (must support environment variables).</typeparam>
    /// <param name="builder">The resource builder.</param>
    /// <param name="serviceName">
    /// The service key used in the AuthProxy <c>Services</c> configuration (e.g. <c>"main"</c>).
    /// </param>
    /// <param name="paths">
    /// The path prefixes to serve anonymously. Each must be a rooted path of literal segments
    /// (e.g. <c>/portal</c>), and is matched case-insensitively on segment boundaries — <c>/portal</c>
    /// covers <c>/portal</c> and <c>/portal/anything</c>, but not <c>/portalx</c>. Anything else is
    /// discarded by AuthProxy, leaving that path authenticated.
    /// </param>
    /// <returns>The same <see cref="IResourceBuilder{T}"/> for chaining.</returns>
    /// <remarks>
    /// Use this for paths an application genuinely serves without a session — a magic-link landing page, a
    /// signed-token report, a public webhook receiver. Without it those paths are unreachable: an
    /// unauthenticated caller is answered with the provider-selection page instead, at <c>HTTP 200</c>, so
    /// a webhook or other non-browser caller records success and never retries.
    /// <para>
    /// Each entry is a prefix and covers everything under it, so name the specific leaf path whenever a
    /// sibling under the same parent is not public. Requests still pass through AuthProxy, which keeps
    /// stripping inbound identity headers, so this makes a path reachable — it does not make it trusted.
    /// The application still authorizes it.
    /// </para>
    /// <para>
    /// The declared prefix is claimed for the whole proxy: an anonymous caller cannot send a
    /// service-selection header, so in a multi-service deployment no other service can serve anything
    /// under a prefix declared here.
    /// </para>
    /// </remarks>
    public static IResourceBuilder<T> WithAnonymousPaths<T>(
        this IResourceBuilder<T> builder,
        string serviceName,
        params string[] paths)
        where T : IResourceWithEnvironment
    {
        var annotation = GetOrCreateAnnotation(builder.Resource);
        annotation.AnonymousPathCounts.TryGetValue(serviceName, out var index);

        foreach (var path in paths)
        {
            builder.WithEnvironment($"{ConfigPrefix}__Services__{serviceName}__AnonymousPaths__{index}", path);
            index++;
        }

        annotation.AnonymousPathCounts[serviceName] = index;

        return builder;
    }

    /// <summary>
    /// Declares the peers whose forwarded headers AuthProxy believes.
    /// </summary>
    /// <typeparam name="T">The resource type (must support environment variables).</typeparam>
    /// <param name="builder">The resource builder.</param>
    /// <param name="addressesOrCidrs">
    /// The addresses and ranges of the infrastructure directly in front of AuthProxy — an ingress
    /// controller, load balancer, service mesh sidecar, or CDN egress range. Write a peer as <c>10.0.0.7</c>
    /// or <c>2001:db8::1</c>, and a range as <c>10.0.0.0/8</c> or <c>2001:db8::/32</c>.
    /// </param>
    /// <returns>The same <see cref="IResourceBuilder{T}"/> for chaining.</returns>
    /// <exception cref="InvalidTrustedProxy">Thrown when an entry is neither an address nor a CIDR range.</exception>
    /// <remarks>
    /// <c>X-Forwarded-For</c> and <c>X-Forwarded-Proto</c> are ordinary request headers, so any caller that
    /// can open a connection to AuthProxy can send them. Until this is declared, AuthProxy believes all of
    /// them: the address recorded against every sign-in is whatever the caller wrote, and a spoofed
    /// <c>X-Forwarded-Proto: https</c> makes an unencrypted request look encrypted, which is what decides
    /// whether the session cookies carry <c>Secure</c>.
    /// <para>
    /// Declare the peers rather than the clients. AuthProxy matches the address it accepted the connection
    /// from, which in a container deployment is the ingress, never a browser.
    /// </para>
    /// <para>
    /// Calling this more than once appends, so the peers may be declared wherever each one is known.
    /// </para>
    /// </remarks>
    public static IResourceBuilder<T> WithTrustedProxies<T>(
        this IResourceBuilder<T> builder,
        params string[] addressesOrCidrs)
        where T : IResourceWithEnvironment
    {
        var annotation = GetOrCreateAnnotation(builder.Resource);
        var index = annotation.TrustedProxyCount;

        foreach (var entry in addressesOrCidrs)
        {
            if (!TrustedProxyEntry.IsResolvable(entry))
            {
                throw new InvalidTrustedProxy(entry);
            }

            builder.WithEnvironment($"{ConfigPrefix}__Ingress__TrustedProxies__{index}", entry);
            index++;
        }

        annotation.TrustedProxyCount = index;

        return builder;
    }

    /// <summary>
    /// Declares how many trusted proxies a request legitimately passes through.
    /// </summary>
    /// <typeparam name="T">The resource type (must support environment variables).</typeparam>
    /// <param name="builder">The resource builder.</param>
    /// <param name="hops">
    /// The number of <c>X-Forwarded-For</c> entries consumed from the right. Defaults in AuthProxy to
    /// <c>1</c> — an ingress controller on its own. A CDN in front of a load balancer is <c>2</c>.
    /// </param>
    /// <returns>The same <see cref="IResourceBuilder{T}"/> for chaining.</returns>
    /// <remarks>
    /// This is what decides which address is reported as the client. Count too few hops and the reported
    /// address is the deployment's own inner proxy; count more hops than the deployment has and the reported
    /// address is whatever the outermost caller chose to write. Every hop counted must itself be declared
    /// through <see cref="WithTrustedProxies{T}"/>, so raising this alone changes nothing.
    /// <para>
    /// Deliberately its own method rather than another optional parameter on
    /// <see cref="WithTrustedProxies{T}"/>. An optional argument is baked into the call site when the app
    /// host is compiled, so adding one would change that method's signature and every already-built app host
    /// would fail to bind against the new package until it is rebuilt.
    /// </para>
    /// </remarks>
    public static IResourceBuilder<T> WithForwardLimit<T>(
        this IResourceBuilder<T> builder,
        int hops)
        where T : IResourceWithEnvironment =>
        builder.WithEnvironment(
            $"{ConfigPrefix}__Ingress__ForwardLimit",
            hops.ToString(CultureInfo.InvariantCulture));

    /// <summary>
    /// Requires every authenticated caller to carry a claim before any request is forwarded.
    /// </summary>
    /// <typeparam name="T">The resource type (must support environment variables).</typeparam>
    /// <param name="builder">The resource builder.</param>
    /// <param name="claim">
    /// The claim type the caller must carry, for example <c>urn:github:organization</c> or <c>roles</c>.
    /// </param>
    /// <param name="anyOf">
    /// The values that satisfy it. Pass none to require only that the claim is present. Values are
    /// compared case-insensitively.
    /// </param>
    /// <returns>The same <see cref="IResourceBuilder{T}"/> for chaining.</returns>
    /// <remarks>
    /// Authentication establishes who a caller is; on a public host that is not the same as deciding
    /// whether they may be here. Without a requirement, any account the configured identity provider will
    /// authenticate — for a public provider such as GitHub, every account on the internet — completes
    /// sign-in and reaches the application.
    /// <para>
    /// Calling this more than once requires <em>all</em> of the claims: several calls compose as an
    /// <em>and</em>, while several values in one call compose as an <em>or</em>. Express "in this
    /// organization and on this team" as two calls, and "in either organization" as one call with two
    /// values.
    /// </para>
    /// </remarks>
    public static IResourceBuilder<T> WithRequiredClaim<T>(
        this IResourceBuilder<T> builder,
        string claim,
        params string[] anyOf)
        where T : IResourceWithEnvironment
    {
        var annotation = GetOrCreateAnnotation(builder.Resource);
        var index = annotation.RequiredClaimCount++;

        return WriteClaimRequirement(builder, $"{ConfigPrefix}__Authorization__RequiredClaims__{index}", claim, anyOf);
    }

    /// <summary>
    /// Requires every authenticated caller reaching a named service to carry a claim.
    /// </summary>
    /// <typeparam name="T">The resource type (must support environment variables).</typeparam>
    /// <param name="builder">The resource builder.</param>
    /// <param name="serviceName">
    /// The service key used in the AuthProxy <c>Services</c> configuration (e.g. <c>"main"</c>).
    /// </param>
    /// <param name="claim">The claim type the caller must carry.</param>
    /// <param name="anyOf">
    /// The values that satisfy it. Pass none to require only that the claim is present.
    /// </param>
    /// <returns>The same <see cref="IResourceBuilder{T}"/> for chaining.</returns>
    /// <remarks>
    /// Applied in addition to anything <see cref="WithRequiredClaim{T}"/> declares, so a service can narrow
    /// who reaches it but never widen it.
    /// </remarks>
    public static IResourceBuilder<T> WithRequiredClaimForService<T>(
        this IResourceBuilder<T> builder,
        string serviceName,
        string claim,
        params string[] anyOf)
        where T : IResourceWithEnvironment
    {
        var annotation = GetOrCreateAnnotation(builder.Resource);
        annotation.ServiceRequiredClaimCounts.TryGetValue(serviceName, out var index);
        annotation.ServiceRequiredClaimCounts[serviceName] = index + 1;

        return WriteClaimRequirement(
            builder,
            $"{ConfigPrefix}__Services__{serviceName}__Authorization__RequiredClaims__{index}",
            claim,
            anyOf);
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
    /// Adds an OIDC provider with an explicit canonical federated identity contract.
    /// </summary>
    /// <typeparam name="T">The resource type, which must support environment variables.</typeparam>
    /// <param name="builder">The resource builder.</param>
    /// <param name="name">The provider display name used to derive the ASP.NET authentication scheme.</param>
    /// <param name="type">The provider brand used by the login user interface.</param>
    /// <param name="authority">The OIDC discovery authority.</param>
    /// <param name="clientId">The registered OIDC client identifier.</param>
    /// <param name="clientSecret">The registered OIDC client secret.</param>
    /// <param name="providerKey">The stable lowercase provider key, independent of display name and scheme.</param>
    /// <param name="subjectClaimType">The one exact claim type used as the canonical provider subject.</param>
    /// <param name="scopes">Optional additional OIDC scopes.</param>
    /// <returns>The same resource builder for chaining.</returns>
    public static IResourceBuilder<T> WithCanonicalOidcProvider<T>(
        this IResourceBuilder<T> builder,
        string name,
        OidcProviderType type,
        string authority,
        string clientId,
        string clientSecret,
        string providerKey,
        string subjectClaimType,
        IEnumerable<string>? scopes = null)
        where T : IResourceWithEnvironment
    {
        builder.WithOidcProvider(name, type, authority, clientId, clientSecret, scopes);
        var index = GetOrCreateAnnotation(builder.Resource).OidcProviderCount - 1;
        var prefix = $"{ConfigPrefix}__Authentication__OidcProviders__{index}__CanonicalIdentity";
        return builder
            .WithEnvironment($"{prefix}__ProviderKey", providerKey)
            .WithEnvironment($"{prefix}__SubjectClaimType", subjectClaimType);
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
    /// Adds an OAuth provider with an explicit canonical federated identity contract.
    /// </summary>
    /// <typeparam name="T">The resource type, which must support environment variables.</typeparam>
    /// <param name="builder">The resource builder.</param>
    /// <param name="name">The provider display name used to derive the ASP.NET authentication scheme.</param>
    /// <param name="type">The provider brand used by the login user interface.</param>
    /// <param name="authorizationEndpoint">The OAuth authorization endpoint.</param>
    /// <param name="tokenEndpoint">The OAuth token endpoint.</param>
    /// <param name="userInformationEndpoint">The authenticated user-information endpoint.</param>
    /// <param name="clientId">The registered OAuth client identifier.</param>
    /// <param name="clientSecret">The registered OAuth client secret.</param>
    /// <param name="providerKey">The stable lowercase provider key, independent of display name and scheme.</param>
    /// <param name="subjectClaimType">
    /// The one exact claim on the resulting authenticated principal used as the canonical provider subject. When the
    /// provider's raw user-information field has another name, map it to this claim through <paramref name="claimMappings"/>.
    /// </param>
    /// <param name="issuer">The explicit absolute HTTPS issuer assigned to this provider registration.</param>
    /// <param name="scopes">Optional additional OAuth scopes.</param>
    /// <param name="claimMappings">
    /// Optional mappings whose key is the resulting principal claim type and whose value is the raw user-information
    /// JSON field. For example, <c>{ ["sub"] = "id" }</c> maps a raw <c>id</c> field to the <c>sub</c> claim selected by
    /// <paramref name="subjectClaimType"/>.
    /// </param>
    /// <returns>The same resource builder for chaining.</returns>
    public static IResourceBuilder<T> WithCanonicalOAuthProvider<T>(
        this IResourceBuilder<T> builder,
        string name,
        OidcProviderType type,
        string authorizationEndpoint,
        string tokenEndpoint,
        string userInformationEndpoint,
        string clientId,
        string clientSecret,
        string providerKey,
        string subjectClaimType,
        string issuer,
        IEnumerable<string>? scopes = null,
        IDictionary<string, string>? claimMappings = null)
        where T : IResourceWithEnvironment
    {
        builder.WithOAuthProvider(
            name,
            type,
            authorizationEndpoint,
            tokenEndpoint,
            userInformationEndpoint,
            clientId,
            clientSecret,
            scopes,
            claimMappings);
        var index = GetOrCreateAnnotation(builder.Resource).OAuthProviderCount - 1;
        var prefix = $"{ConfigPrefix}__Authentication__OAuthProviders__{index}__CanonicalIdentity";
        return builder
            .WithEnvironment($"{prefix}__ProviderKey", providerKey)
            .WithEnvironment($"{prefix}__SubjectClaimType", subjectClaimType)
            .WithEnvironment($"{prefix}__Issuer", issuer);
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
    /// <param name="tenantsEndpoint">
    /// Absolute URL of the endpoint that returns selectable tenants for the current authenticated user.
    /// Expected response shape is an array of <c>{ "id": "...", "name": "..." }</c> objects.
    /// When <see langword="null"/> the endpoint is omitted and must be supplied via other configuration.
    /// </param>
    /// <returns>The same <see cref="IResourceBuilder{T}"/> for chaining.</returns>
    public static IResourceBuilder<T> WithSelectionTenantResolution<T>(
        this IResourceBuilder<T> builder,
        string? tenantsEndpoint = null)
        where T : IResourceWithEnvironment
    {
        var annotation = GetOrCreateAnnotation(builder.Resource);
        var idx = annotation.TenantResolutionCount++;
        var prefix = $"{ConfigPrefix}__TenantResolutions__{idx}";

        builder.WithEnvironment($"{prefix}__Strategy", "Selection");
        if (!string.IsNullOrEmpty(tenantsEndpoint))
        {
            builder.WithEnvironment($"{prefix}__Options__TenantsEndpoint", tenantsEndpoint);
        }

        return builder;
    }

    /// <summary>
    /// Adds a cookie-selection-based tenant resolution strategy to AuthProxy, deriving the tenants
    /// endpoint URL from the specified Aspire service resource.
    /// </summary>
    /// <typeparam name="T">The resource type (must support environment variables).</typeparam>
    /// <param name="builder">The resource builder.</param>
    /// <param name="serviceResource">The Aspire resource that hosts the selectable-tenants endpoint.</param>
    /// <param name="route">
    /// The route on the service that returns the selectable tenant list,
    /// e.g. <c>"/api/tenants/selectable"</c>.
    /// </param>
    /// <param name="endpointName">The endpoint name to use.  Defaults to <c>"http"</c>.</param>
    /// <returns>The same <see cref="IResourceBuilder{T}"/> for chaining.</returns>
    public static IResourceBuilder<T> WithSelectionTenantResolution<T>(
        this IResourceBuilder<T> builder,
        IResourceBuilder<IResourceWithEndpoints> serviceResource,
        string route,
        string endpointName = "http")
        where T : IResourceWithEnvironment
    {
        var annotation = GetOrCreateAnnotation(builder.Resource);
        var idx = annotation.TenantResolutionCount++;
        var prefix = $"{ConfigPrefix}__TenantResolutions__{idx}";
        var endpoint = serviceResource.GetEndpoint(endpointName);

        builder.WithEnvironment($"{prefix}__Strategy", "Selection");
        builder.WithEnvironment(context =>
            context.EnvironmentVariables[$"{prefix}__Options__TenantsEndpoint"] =
                ReferenceExpression.Create($"{endpoint}{route}"));

        return builder;
    }

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

    /// <summary>
    /// Configures AuthProxy to verify that a resolved tenant actually exists by calling an endpoint
    /// on the specified Aspire service resource.
    /// </summary>
    /// <typeparam name="T">The resource type (must support environment variables).</typeparam>
    /// <param name="builder">The resource builder.</param>
    /// <param name="serviceResource">The Aspire resource that hosts the tenant-verification endpoint.</param>
    /// <param name="routeTemplate">
    /// The route on the service, including the <c>{tenantId}</c> placeholder,
    /// e.g. <c>"/api/tenants/{tenantId}"</c>.
    /// </param>
    /// <param name="endpointName">The endpoint name to use.  Defaults to <c>"http"</c>.</param>
    /// <returns>The same <see cref="IResourceBuilder{T}"/> for chaining.</returns>
    public static IResourceBuilder<T> WithTenantVerification<T>(
        this IResourceBuilder<T> builder,
        IResourceBuilder<IResourceWithEndpoints> serviceResource,
        string routeTemplate,
        string endpointName = "http")
        where T : IResourceWithEnvironment
    {
        var endpoint = serviceResource.GetEndpoint(endpointName);
        return builder.WithEnvironment(context =>
            context.EnvironmentVariables[$"{ConfigPrefix}__TenantVerification__UrlTemplate"] =
                ReferenceExpression.Create($"{endpoint}{routeTemplate}"));
    }

    /// <summary>
    /// Configures the AuthProxy invite system with the core invite settings.
    /// </summary>
    /// <typeparam name="T">The resource type (must support environment variables).</typeparam>
    /// <param name="builder">The resource builder.</param>
    /// <param name="publicKeyPem">PEM-encoded RSA public key used to verify invite token signatures.</param>
    /// <param name="exchangeUrl">
    /// Absolute URL of the invite-exchange endpoint called after a successful login with a pending invite token,
    /// e.g. <c>https://lobby.example.com/_invite/exchange</c>.
    /// </param>
    /// <param name="issuer">
    /// Expected <c>iss</c> claim value. Leave <see langword="null"/> to skip issuer validation.
    /// </param>
    /// <param name="audience">
    /// Expected <c>aud</c> claim value. Leave <see langword="null"/> to skip audience validation.
    /// </param>
    /// <param name="tenantClaim">
    /// Claim in the invite token that carries the tenant ID string (used for tenant-issued invite detection).
    /// Leave <see langword="null"/> to use the AuthProxy default.
    /// </param>
    /// <param name="subjectAlreadyExistsUrl">
    /// URL to redirect to when the exchange endpoint returns HTTP 409 (subject already registered).
    /// Leave <see langword="null"/> to serve the built-in <c>invitation-subject-already-exists.html</c> page.
    /// </param>
    /// <returns>The same <see cref="IResourceBuilder{T}"/> for chaining.</returns>
    public static IResourceBuilder<T> WithInvite<T>(
        this IResourceBuilder<T> builder,
        string publicKeyPem,
        string exchangeUrl,
        string? issuer = null,
        string? audience = null,
        string? tenantClaim = null,
        string? subjectAlreadyExistsUrl = null)
        where T : IResourceWithEnvironment
    {
        const string prefix = $"{ConfigPrefix}__Invite";

        builder
            .WithEnvironment($"{prefix}__PublicKeyPem", publicKeyPem)
            .WithEnvironment($"{prefix}__ExchangeUrl", exchangeUrl);

        if (!string.IsNullOrEmpty(issuer))
        {
            builder.WithEnvironment($"{prefix}__Issuer", issuer);
        }

        if (!string.IsNullOrEmpty(audience))
        {
            builder.WithEnvironment($"{prefix}__Audience", audience);
        }

        if (!string.IsNullOrEmpty(tenantClaim))
        {
            builder.WithEnvironment($"{prefix}__TenantClaim", tenantClaim);
        }

        if (!string.IsNullOrEmpty(subjectAlreadyExistsUrl))
        {
            builder.WithEnvironment($"{prefix}__SubjectAlreadyExistsUrl", subjectAlreadyExistsUrl);
        }

        return builder;
    }

    /// <summary>
    /// Enables the signed two-stage invitation protocol for an already configured invite system.
    /// </summary>
    /// <typeparam name="T">The resource type, which must support environment variables.</typeparam>
    /// <param name="builder">The resource builder.</param>
    /// <param name="stageUrl">The absolute invitation staging endpoint.</param>
    /// <param name="issuer">The issuer AuthProxy writes to invitation attestations.</param>
    /// <param name="audience">The audience expected by the invitation authority.</param>
    /// <param name="keyId">The identifier of the active RSA signing key.</param>
    /// <param name="privateKeyPem">The PEM-encoded RSA private key supplied from a secret provider.</param>
    /// <param name="lifetime">The attestation lifetime. The default and maximum are 60 seconds.</param>
    /// <returns>The same resource builder for chaining.</returns>
    /// <exception cref="ArgumentOutOfRangeException">Thrown when <paramref name="lifetime"/> is shorter than 10 seconds or longer than 60 seconds.</exception>
    /// <remarks>
    /// Configure the invitation authority with the matching public key before activating a new key identifier.
    /// AuthProxy writes the private value to an environment variable and never logs it.
    /// </remarks>
    public static IResourceBuilder<T> WithSignedInvitationAttestations<T>(
        this IResourceBuilder<T> builder,
        string stageUrl,
        string issuer,
        string audience,
        string keyId,
        string privateKeyPem,
        TimeSpan? lifetime = null)
        where T : IResourceWithEnvironment
    {
        const string prefix = $"{ConfigPrefix}__Invite";
        var attestationLifetime = lifetime ?? TimeSpan.FromSeconds(60);
        if (attestationLifetime < TimeSpan.FromSeconds(10) || attestationLifetime > TimeSpan.FromSeconds(60))
        {
            throw new ArgumentOutOfRangeException(
                nameof(lifetime),
                lifetime,
                "Invitation attestation lifetime must be between 10 and 60 seconds.");
        }

        return builder
            .WithEnvironment($"{prefix}__StageUrl", stageUrl)
            .WithEnvironment($"{prefix}__Attestation__Issuer", issuer)
            .WithEnvironment($"{prefix}__Attestation__Audience", audience)
            .WithEnvironment($"{prefix}__Attestation__ActiveKeyId", keyId)
            .WithEnvironment($"{prefix}__Attestation__SigningKeys__0__KeyId", keyId)
            .WithEnvironment($"{prefix}__Attestation__SigningKeys__0__PrivateKeyPem", privateKeyPem)
            .WithEnvironment($"{prefix}__Attestation__Lifetime", attestationLifetime.ToString("c"));
    }

    /// <summary>
    /// Configures the AuthProxy invite system, deriving the exchange endpoint URL from the specified Aspire service resource.
    /// </summary>
    /// <typeparam name="T">The resource type (must support environment variables).</typeparam>
    /// <param name="builder">The resource builder.</param>
    /// <param name="publicKeyPem">PEM-encoded RSA public key used to verify invite token signatures.</param>
    /// <param name="exchangeServiceResource">The Aspire resource that hosts the invite-exchange endpoint.</param>
    /// <param name="exchangeRoute">
    /// The route on the exchange service, e.g. <c>"/internal/invites/exchange"</c>.
    /// </param>
    /// <param name="exchangeEndpointName">The endpoint name to use for the exchange service.  Defaults to <c>"http"</c>.</param>
    /// <param name="issuer">
    /// Expected <c>iss</c> claim value. Leave <see langword="null"/> to skip issuer validation.
    /// </param>
    /// <param name="audience">
    /// Expected <c>aud</c> claim value. Leave <see langword="null"/> to skip audience validation.
    /// </param>
    /// <param name="tenantClaim">
    /// Claim in the invite token that carries the tenant ID string (used for tenant-issued invite detection).
    /// Leave <see langword="null"/> to use the AuthProxy default.
    /// </param>
    /// <param name="subjectAlreadyExistsUrl">
    /// URL to redirect to when the exchange endpoint returns HTTP 409 (subject already registered).
    /// Leave <see langword="null"/> to serve the built-in <c>invitation-subject-already-exists.html</c> page.
    /// </param>
    /// <returns>The same <see cref="IResourceBuilder{T}"/> for chaining.</returns>
    public static IResourceBuilder<T> WithInvite<T>(
        this IResourceBuilder<T> builder,
        string publicKeyPem,
        IResourceBuilder<IResourceWithEndpoints> exchangeServiceResource,
        string exchangeRoute,
        string exchangeEndpointName = "http",
        string? issuer = null,
        string? audience = null,
        string? tenantClaim = null,
        string? subjectAlreadyExistsUrl = null)
        where T : IResourceWithEnvironment
    {
        const string prefix = $"{ConfigPrefix}__Invite";

        var endpoint = exchangeServiceResource.GetEndpoint(exchangeEndpointName);
        builder
            .WithEnvironment($"{prefix}__PublicKeyPem", publicKeyPem)
            .WithEnvironment(context =>
                context.EnvironmentVariables[$"{prefix}__ExchangeUrl"] =
                    ReferenceExpression.Create($"{endpoint}{exchangeRoute}"));

        if (!string.IsNullOrEmpty(issuer))
        {
            builder.WithEnvironment($"{prefix}__Issuer", issuer);
        }

        if (!string.IsNullOrEmpty(audience))
        {
            builder.WithEnvironment($"{prefix}__Audience", audience);
        }

        if (!string.IsNullOrEmpty(tenantClaim))
        {
            builder.WithEnvironment($"{prefix}__TenantClaim", tenantClaim);
        }

        if (!string.IsNullOrEmpty(subjectAlreadyExistsUrl))
        {
            builder.WithEnvironment($"{prefix}__SubjectAlreadyExistsUrl", subjectAlreadyExistsUrl);
        }

        return builder;
    }

    /// <summary>
    /// Adds a claim-forwarding entry to the AuthProxy invite system.
    /// When a pending invite cookie exists, AuthProxy reads the specified claim from the invite token
    /// and forwards it as part of the principal sent to each <c>/.cratis/me</c> identity details endpoint.
    /// Call this method once per claim to forward; multiple calls accumulate entries.
    /// </summary>
    /// <typeparam name="T">The resource type (must support environment variables).</typeparam>
    /// <param name="builder">The resource builder.</param>
    /// <param name="fromClaimType">Claim type to read from the invite token payload.</param>
    /// <param name="toClaimType">
    /// Claim type to emit in the forwarded principal.
    /// When <see langword="null"/> the original <paramref name="fromClaimType"/> is used.
    /// </param>
    /// <returns>The same <see cref="IResourceBuilder{T}"/> for chaining.</returns>
    public static IResourceBuilder<T> WithInviteClaimForwarding<T>(
        this IResourceBuilder<T> builder,
        string fromClaimType,
        string? toClaimType = null)
        where T : IResourceWithEnvironment
    {
        var annotation = GetOrCreateAnnotation(builder.Resource);
        var idx = annotation.InviteClaimForwardingCount++;
        var prefix = $"{ConfigPrefix}__Invite__ClaimsToForward__{idx}";

        builder.WithEnvironment($"{prefix}__FromClaimType", fromClaimType);
        if (!string.IsNullOrEmpty(toClaimType))
        {
            builder.WithEnvironment($"{prefix}__ToClaimType", toClaimType);
        }

        return builder;
    }

    /// <summary>
    /// Configures the AuthProxy lobby frontend endpoint.
    /// The lobby is the service users without a resolved tenant are redirected to
    /// while they complete the onboarding / invite-exchange process.
    /// </summary>
    /// <typeparam name="T">The resource type (must support environment variables).</typeparam>
    /// <param name="builder">The resource builder.</param>
    /// <param name="serviceResource">The Aspire resource that exposes the lobby frontend.</param>
    /// <param name="endpointName">The endpoint name to use. Defaults to <c>"http"</c>.</param>
    /// <returns>The same <see cref="IResourceBuilder{T}"/> for chaining.</returns>
    public static IResourceBuilder<T> WithLobbyFrontend<T>(
        this IResourceBuilder<T> builder,
        IResourceBuilder<IResourceWithEndpoints> serviceResource,
        string endpointName = "http")
        where T : IResourceWithEnvironment
    {
        var endpoint = serviceResource.GetEndpoint(endpointName);
        return builder.WithEnvironment(context =>
            context.EnvironmentVariables[$"{ConfigPrefix}__Invite__Lobby__Frontend__BaseUrl"] =
                ReferenceExpression.Create($"{endpoint}/"));
    }

    /// <summary>
    /// Configures the AuthProxy lobby backend (API) endpoint.
    /// The backend is optional — add it only when the lobby service exposes an API that
    /// AuthProxy should be able to call or proxy.
    /// </summary>
    /// <typeparam name="T">The resource type (must support environment variables).</typeparam>
    /// <param name="builder">The resource builder.</param>
    /// <param name="serviceResource">The Aspire resource that exposes the lobby backend.</param>
    /// <param name="endpointName">The endpoint name to use. Defaults to <c>"http"</c>.</param>
    /// <returns>The same <see cref="IResourceBuilder{T}"/> for chaining.</returns>
    public static IResourceBuilder<T> WithLobbyBackend<T>(
        this IResourceBuilder<T> builder,
        IResourceBuilder<IResourceWithEndpoints> serviceResource,
        string endpointName = "http")
        where T : IResourceWithEnvironment
    {
        var endpoint = serviceResource.GetEndpoint(endpointName);
        return builder.WithEnvironment(context =>
            context.EnvironmentVariables[$"{ConfigPrefix}__Invite__Lobby__Backend__BaseUrl"] =
                ReferenceExpression.Create($"{endpoint}/"));
    }

    /// <summary>
    /// Configures the AuthProxy lobby registration URL directly.
    /// This is the URL users are redirected to after completing the AuthProxy registration bootstrap flow.
    /// </summary>
    /// <typeparam name="T">The resource type (must support environment variables).</typeparam>
    /// <param name="builder">The resource builder.</param>
    /// <param name="registrationUrl">Absolute URL for the lobby registration flow.</param>
    /// <returns>The same <see cref="IResourceBuilder{T}"/> for chaining.</returns>
    public static IResourceBuilder<T> WithLobbyRegistration<T>(
        this IResourceBuilder<T> builder,
        string registrationUrl)
        where T : IResourceWithEnvironment =>
        builder.WithEnvironment($"{ConfigPrefix}__Invite__Lobby__Registration__BaseUrl", registrationUrl);

    /// <summary>
    /// Configures the AuthProxy lobby registration URL from the specified Aspire service resource.
    /// </summary>
    /// <typeparam name="T">The resource type (must support environment variables).</typeparam>
    /// <param name="builder">The resource builder.</param>
    /// <param name="serviceResource">The Aspire resource that exposes the lobby registration endpoint.</param>
    /// <param name="route">The route on the lobby service that starts registration, e.g. <c>"/register"</c>.</param>
    /// <param name="endpointName">The endpoint name to use. Defaults to <c>"http"</c>.</param>
    /// <returns>The same <see cref="IResourceBuilder{T}"/> for chaining.</returns>
    public static IResourceBuilder<T> WithLobbyRegistration<T>(
        this IResourceBuilder<T> builder,
        IResourceBuilder<IResourceWithEndpoints> serviceResource,
        string route,
        string endpointName = "http")
        where T : IResourceWithEnvironment
    {
        var endpoint = serviceResource.GetEndpoint(endpointName);
        return builder.WithEnvironment(context =>
            context.EnvironmentVariables[$"{ConfigPrefix}__Invite__Lobby__Registration__BaseUrl"] =
                ReferenceExpression.Create($"{endpoint}{route}"));
    }

    static IResourceBuilder<T> AddTenantResolution<T>(IResourceBuilder<T> builder, string strategy)
        where T : IResourceWithEnvironment
    {
        var annotation = GetOrCreateAnnotation(builder.Resource);
        var idx = annotation.TenantResolutionCount++;
        return builder.WithEnvironment($"{ConfigPrefix}__TenantResolutions__{idx}__Strategy", strategy);
    }

    /// <summary>
    /// Writes one claim requirement at the given configuration prefix.
    /// </summary>
    /// <typeparam name="T">The resource type (must support environment variables).</typeparam>
    /// <param name="builder">The resource builder.</param>
    /// <param name="prefix">The indexed configuration prefix to write under.</param>
    /// <param name="claim">The claim type the caller must carry.</param>
    /// <param name="anyOf">The values that satisfy it.</param>
    /// <returns>The same <see cref="IResourceBuilder{T}"/> for chaining.</returns>
    static IResourceBuilder<T> WriteClaimRequirement<T>(
        IResourceBuilder<T> builder,
        string prefix,
        string claim,
        string[] anyOf)
        where T : IResourceWithEnvironment
    {
        builder.WithEnvironment($"{prefix}__Claim", claim);

        for (var i = 0; i < anyOf.Length; i++)
        {
            builder.WithEnvironment($"{prefix}__AnyOf__{i}", anyOf[i]);
        }

        return builder;
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
