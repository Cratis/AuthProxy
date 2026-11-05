// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Yarp.ReverseProxy.Transforms;
using Yarp.ReverseProxy.Transforms.Builder;

namespace Cratis.AuthProxy.Security.given;

/// <summary>A running deployment with signed, independently signed, unsigned and explicitly signed tenant flows.</summary>
public class ForwardedIdentityHarness : BearerRouteHarness
{
    /// <summary>The signed browser-session service host.</summary>
    public const string SignedHost = "signed.example.test";

    /// <summary>The second signed service host.</summary>
    public const string OtherHost = "other.example.test";

    /// <summary>The unsigned legacy service host.</summary>
    public const string LegacyHost = "legacy.example.test";

    /// <summary>The anonymous path on the signed service.</summary>
    public const string AnonymousPath = "/hooks/inbound";

    /// <summary>The path where a test transform deliberately creates unsignable final headers.</summary>
    public const string RefusedPath = "/api/unsignable";

    /// <summary>Initializes a new instance of the <see cref="ForwardedIdentityHarness"/> class.</summary>
    public ForwardedIdentityHarness()
    {
        ApplicationOrigin = ForwardedIdentityOrigin.Start("signed-backend", "active-1", 42).GetAwaiter().GetResult();
        Other = ForwardedIdentityOrigin.Start("other-backend", "other-1", 43).GetAwaiter().GetResult();
        Tenants = ForwardedIdentityOrigin.Start("tenant-backend", "tenants-1", 44).GetAwaiter().GetResult();
    }

    /// <summary>Gets the signed application's independently verifying origin.</summary>
    public ForwardedIdentityOrigin ApplicationOrigin { get; }

    /// <summary>Gets a differently keyed application's verifying origin.</summary>
    public ForwardedIdentityOrigin Other { get; }

    /// <summary>Gets the separately configured tenant-list origin.</summary>
    public ForwardedIdentityOrigin Tenants { get; }

    /// <summary>Creates a client without automatic redirects or cookie persistence.</summary>
    /// <returns>The test client.</returns>
    public HttpClient CreateSecurityClient() => CreateBearerClient();

    /// <summary>Builds a simulated browser cookie-session request using the existing authentication fixture.</summary>
    /// <param name="host">The routed service's host.</param>
    /// <param name="path">The requested path and query.</param>
    /// <returns>The authenticated request.</returns>
    public static HttpRequestMessage Session(string host, string path)
    {
        var request = SecurityHarness.Authenticated(HttpMethod.Get, path, SecurityHarness.UniqueUser("signing"));
        request.Headers.Host = host;
        request.Headers.Add(UpstreamRequestsHarness.SessionHeader, "session");
        return request;
    }

    /// <inheritdoc/>
    protected override void AddSettings(IDictionary<string, string?> settings)
    {
        const string root = C.AuthProxy.SectionKey;
        settings[$"{root}:Services:app:Hosts:0"] = SignedHost;
        settings[$"{root}:Services:app:Backend:BaseUrl"] = ApplicationOrigin.BaseUrl + "/base";
        settings[$"{root}:Services:app:Frontend:BaseUrl"] = ApplicationOrigin.BaseUrl + "/base";
        settings[$"{root}:Services:app:IdentityVerification"] = nameof(C.IdentityVerificationMode.Required);
        for (var index = 0; index < 3; index++) settings[$"{root}:Services:app:BearerRoutes:{index}:AcceptWithoutIdentityVerification"] = "true";
        settings[$"{root}:Services:app:AnonymousPaths:0"] = AnonymousPath;
        Signing(settings, $"{root}:Services:app:ForwardedIdentity", ApplicationOrigin);

        settings[$"{root}:Services:other:Hosts:0"] = OtherHost;
        settings[$"{root}:Services:other:Backend:BaseUrl"] = Other.BaseUrl;
        settings[$"{root}:Services:other:Frontend:BaseUrl"] = Other.BaseUrl;
        settings[$"{root}:Services:other:ResolveIdentityDetails"] = "false";
        settings[$"{root}:Services:other:IdentityVerification"] = nameof(C.IdentityVerificationMode.BestEffort);
        Signing(settings, $"{root}:Services:other:ForwardedIdentity", Other);

        settings[$"{root}:Services:legacy:Hosts:0"] = LegacyHost;
        settings[$"{root}:Services:legacy:Backend:BaseUrl"] = Origin.BaseUrl;
        settings[$"{root}:Services:legacy:Frontend:BaseUrl"] = Origin.BaseUrl;
        settings[$"{root}:Services:legacy:ResolveIdentityDetails"] = "false";
        settings[$"{root}:Services:legacy:IdentityVerification"] = nameof(C.IdentityVerificationMode.BestEffort);

        settings[$"{root}:TenantResolutions:1:Strategy"] = nameof(C.TenantSourceIdentifierResolverType.Selection);
        settings[$"{root}:TenantResolutions:1:Options:TenantsEndpoint"] = Tenants.BaseUrl + "/tenants";
        Signing(settings, $"{root}:TenantResolutions:1:Options:ForwardedIdentity", Tenants);
    }

    /// <inheritdoc/>
    protected override void ConfigureHost(IWebHostBuilder builder) => builder.ConfigureTestServices(services =>
    {
        services.AddSingleton<IStartupFilter, SimulatedCookieSession>();
        services.AddSingleton<ITransformProvider, UnsignableRequestTransform>();
    });

    /// <inheritdoc/>
    protected override void Dispose(bool disposing)
    {
        base.Dispose(disposing);
        if (!disposing) return;
        ApplicationOrigin.DisposeAsync().AsTask().GetAwaiter().GetResult();
        Other.DisposeAsync().AsTask().GetAwaiter().GetResult();
        Tenants.DisposeAsync().AsTask().GetAwaiter().GetResult();
    }

    static void Signing(IDictionary<string, string?> settings, string path, ForwardedIdentityOrigin origin)
    {
        settings[$"{path}:Audience"] = origin.Audience;
        settings[$"{path}:KeyId"] = origin.KeyId;
        settings[$"{path}:SecretBase64"] = Convert.ToBase64String(origin.Secret.Span);
    }

    sealed class UnsignableRequestTransform : ITransformProvider
    {
        public void ValidateRoute(TransformRouteValidationContext context)
        {
        }

        public void ValidateCluster(TransformClusterValidationContext context)
        {
        }

        public void Apply(TransformBuilderContext context) => context.AddRequestTransform(request =>
        {
            if (request.HttpContext.Request.Path == RefusedPath)
            {
                request.ProxyRequest.Headers.TryAddWithoutValidation(Headers.PrincipalId, "duplicate");
            }
            return ValueTask.CompletedTask;
        });
    }

    sealed class SimulatedCookieSession : IStartupFilter
    {
        public Action<IApplicationBuilder> Configure(Action<IApplicationBuilder> next) => app =>
        {
            app.Use(async (context, proceed) =>
            {
                if (context.Request.Headers.Remove(UpstreamRequestsHarness.SessionHeader))
                {
                    context.Items[Authentication.AuthenticationServiceCollectionExtensions.SelectedSchemeItemKey] = CookieAuthenticationDefaults.AuthenticationScheme;
                }
                await proceed();
            });
            next(app);
        };
    }
}
