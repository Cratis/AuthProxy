// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Hosting;

namespace Cratis.AuthProxy.Scenarios.when_invitation_link_is_used;

/// <summary>
/// Extends <see cref="MultipleProvidersAuthProxyFactory"/> with a frontend endpoint, so the deployment is
/// routed the way a real one is.
/// </summary>
/// <remarks>
/// Every other scenario here declares a backend and nothing else, and a backend-only service is routed at
/// <c>/api/{**catch-all}</c> alone — so an invitation path matches no route, is selected onto no endpoint,
/// and reaches the invite middleware whatever the authorization step would have done with it. A real
/// deployment declares a frontend as well (Studio sets <c>Services:{key}:Frontend:BaseUrl</c> alongside the
/// backend), and a frontend is routed at <c>/{**catch-all}</c> — which matches every path there is,
/// including the two the proxy answers itself.
/// <para>
/// That single configuration difference is why an invitation link looped in production while every
/// invitation spec passed: the scenarios were run on the one routing shape in which the defect cannot
/// occur. Declaring the frontend here is the whole point of this factory — it is what makes these
/// scenarios exercise the pipeline a deployment actually runs.
/// </para>
/// </remarks>
public class FrontendRoutedAuthProxyFactory : MultipleProvidersAuthProxyFactory
{
    /// <summary>The frontend endpoint whose catch-all route covers every path.</summary>
    public const string FrontendBaseUrl = "http://frontend.test/";

    /// <inheritdoc/>
    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        // The development settings declare a second service of their own, and a plain catch-all is only
        // emitted for a deployment that has exactly one - so leaving them loaded means every route is
        // selected by a header or query parameter, a browser's invitation request matches none of them, and
        // the scenario silently stops covering the routing shape it exists to cover.
        builder.UseEnvironment(Environments.Production);
        base.ConfigureWebHost(builder);
        builder.ConfigureAppConfiguration((_, config) =>
        {
            config.AddInMemoryCollection(new Dictionary<string, string?>
            {
                [$"{C.AuthProxy.SectionKey}:Services:test:Frontend:BaseUrl"] = FrontendBaseUrl,
            });
        });
    }
}
