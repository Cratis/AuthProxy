// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.Configuration;

namespace Cratis.AuthProxy.Scenarios.when_a_bundled_web_asset_is_requested;

/// <summary>
/// A proxy with a configured backend service — so its reverse-proxy route exists, the way it always does
/// in a real deployment — and a bundled web asset under <c>wwwroot</c>, the way the login-selection SPA's
/// build output is.
/// </summary>
public class AuthProxyFactory : WebApplicationFactory<Program>
{
    public const string BackendBaseUrl = "http://backend.test/";
    public const string TenantId = "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb";
    public const string AssetPath = "/assets/app.js";
    public const string AssetContent = "console.log('bundled web asset');";

    readonly string _webRootPath = Path.Combine(Path.GetTempPath(), Path.GetRandomFileName());

    public AuthProxyFactory()
    {
        var assetsDirectory = Path.Combine(_webRootPath, "assets");
        Directory.CreateDirectory(assetsDirectory);
        File.WriteAllText(Path.Combine(assetsDirectory, "app.js"), AssetContent);
    }

    protected override void Dispose(bool disposing)
    {
        base.Dispose(disposing);
        if (disposing && Directory.Exists(_webRootPath))
        {
            Directory.Delete(_webRootPath, recursive: true);
        }
    }

    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        builder
            .UseEnvironment("Production")
            .UseWebRoot(_webRootPath)
            .ConfigureAppConfiguration((_, config) => config.AddInMemoryCollection(new Dictionary<string, string?>
            {
                // A configured backend is what gives the reverse proxy a real route to match — the
                // condition every production deployment is always in, and the one the bug depended on.
                [$"{C.AuthProxy.SectionKey}:Services:app:Backend:BaseUrl"] = BackendBaseUrl,
                [$"{C.AuthProxy.SectionKey}:Services:app:Frontend:BaseUrl"] = BackendBaseUrl,

                [$"{C.AuthProxy.SectionKey}:TenantResolutions:0:Strategy"] = nameof(C.TenantSourceIdentifierResolverType.Specified),
                [$"{C.AuthProxy.SectionKey}:TenantResolutions:0:Options:TenantId"] = TenantId,
            }));
    }

    public HttpClient CreateAnonymousClient() =>
        CreateClient(new WebApplicationFactoryClientOptions { AllowAutoRedirect = false });
}
