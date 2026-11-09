// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Logging;

namespace Cratis.AuthProxy.Security.given;

/// <summary>
/// The bearer-route deployment with introspection configured: <c language="text">/mcp</c> asks the endpoint on every
/// request and refuses when it cannot be asked, <c language="text">/v1</c> reuses an active answer for up to thirty seconds and
/// accepts local validation alone when the endpoint cannot be asked, and <c language="text">/offline</c> has none.
/// </summary>
public class IntrospectionHarness : BearerRouteHarness
{
    /// <summary>The route that does not use the answer cache.</summary>
    public const string MarkedRoute = RoutePrefix;

    /// <summary>The route whose issuer's answers are cached.</summary>
    public const string CachedRoute = ForwardingRoutePrefix;

    /// <summary>
    /// Initializes a new instance of the <see cref="IntrospectionHarness"/> class.
    /// </summary>
    public IntrospectionHarness()
    {
        Endpoint = StubIntrospectionEndpoint.Start().GetAwaiter().GetResult();
    }

    /// <summary>
    /// Gets the introspection endpoint.
    /// </summary>
    public StubIntrospectionEndpoint Endpoint { get; }

    /// <summary>
    /// Gets what AuthProxy logged at warning level or above.
    /// </summary>
    public CapturedLogs Logs { get; } = new();

    /// <inheritdoc/>
    protected override void AddSettings(IDictionary<string, string?> settings)
    {
        const string service = $"{C.AuthProxy.SectionKey}:Services:app:BearerRoutes";

        Configure(settings, $"{service}:0", StubIntrospectionEndpoint.Path, "0");
        Configure(settings, $"{service}:1", StubIntrospectionEndpoint.CachedPath, "00:00:30");
        settings[$"{service}:1:{nameof(C.BearerRoute.IntrospectionUnavailable)}"] = nameof(C.IntrospectionFailurePolicy.Accept);
    }

    /// <inheritdoc/>
    protected override void ConfigureHost(IWebHostBuilder builder) =>
        builder.ConfigureLogging(logging => logging.AddProvider(Logs));

    /// <inheritdoc/>
    protected override void Dispose(bool disposing)
    {
        base.Dispose(disposing);
        if (disposing)
        {
            Endpoint.DisposeAsync().AsTask().GetAwaiter().GetResult();
        }
    }

    void Configure(IDictionary<string, string?> settings, string route, string path, string cacheDuration)
    {
        const string at = nameof(C.BearerRoute.Issuers);
        var introspection = $"{route}:{at}:0:{nameof(C.BearerIssuer.Introspection)}";
        settings[$"{introspection}:{nameof(C.BearerIssuerIntrospection.Endpoint)}"] = $"{Endpoint.BaseUrl}{path}";
        settings[$"{introspection}:{nameof(C.BearerIssuerIntrospection.ClientId)}"] = StubIntrospectionEndpoint.ClientId;
        settings[$"{introspection}:{nameof(C.BearerIssuerIntrospection.ClientSecret)}"] = StubIntrospectionEndpoint.ClientSecret;
        settings[$"{introspection}:{nameof(C.BearerIssuerIntrospection.CacheDuration)}"] = cacheDuration;
        settings[$"{introspection}:{nameof(C.BearerIssuerIntrospection.Timeout)}"] = "00:00:01";
    }
}
