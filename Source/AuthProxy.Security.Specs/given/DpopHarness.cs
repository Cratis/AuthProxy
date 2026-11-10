// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.BearerRoutes.Dpop;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;

namespace Cratis.AuthProxy.Security.given;

public class DpopHarness(IDpopReplayStore store) : BearerRouteHarness
{
    protected override void AddSettings(IDictionary<string, string?> settings)
    {
        const string route = $"{C.AuthProxy.SectionKey}:Services:app:BearerRoutes:0";
        settings[$"{route}:Dpop:PublicOrigin"] = "https://direct.example.test";
        settings[$"{C.Dpop.SectionKey}:ReplayStore:Redis:ConnectionString"] = "replay.example.test:6379";
    }

    protected override void ConfigureHost(IWebHostBuilder builder) => builder.ConfigureTestServices(services => services.AddSingleton(store));
}
