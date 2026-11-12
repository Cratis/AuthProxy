// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Hosting.Server;
using Microsoft.AspNetCore.Hosting.Server.Features;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

namespace Cratis.AuthProxy.Security.given;

/// <summary>The real cookie-session pipeline and YARP over Kestrel, targeting an Arc origin.</summary>
public class ArcCratisHarness : SessionCookieHarness
{
    public ArcCratisHarness()
    {
        UseKestrel();
        Arc = ArcCratisBackend.Start().GetAwaiter().GetResult();
    }

    public ArcCratisBackend Arc { get; }

    public HttpClient CreateArcClient()
    {
        StartServer();
        var address = Services.GetRequiredService<IServer>().Features.Get<IServerAddressesFeature>().Addresses.Single();
        return CreateClient(new WebApplicationFactoryClientOptions
        {
            BaseAddress = new Uri(address),
            AllowAutoRedirect = false,
            HandleCookies = false,
        });
    }

    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        base.ConfigureWebHost(builder);
        builder.UseUrls("http://127.0.0.1:0")
            .ConfigureAppConfiguration((_, config) => config.AddInMemoryCollection(new Dictionary<string, string?>
            {
                [$"{C.AuthProxy.SectionKey}:Services:console:Backend:BaseUrl"] = Arc.BaseUrl,
                [$"{C.AuthProxy.SectionKey}:Services:console:Frontend:BaseUrl"] = Arc.BaseUrl,
            }));
    }

    protected override void Dispose(bool disposing)
    {
        base.Dispose(disposing);
        if (disposing) Arc.DisposeAsync().AsTask().GetAwaiter().GetResult();
    }
}
