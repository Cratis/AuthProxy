// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.AspNetCore.Hosting;

namespace Cratis.AuthProxy.Scenarios.when_anonymous_paths_are_configured;

/// <summary>
/// The same host with exactly one service configured, which is the deployment shape that puts a catch-all
/// route in the table.
/// <para>
/// The other factories in this folder inherit a second service from the host's development settings, so
/// every generated route there is selected by a header or a query parameter and a declared prefix has no
/// competition. With a single service the proxy also emits <c>/{**catch-all}</c> carrying the
/// authenticated-user policy, which overlaps every declared prefix — so this is the shape where the
/// declared route has to win on order, and the shape a single-application deployment actually runs.
/// </para>
/// <para>
/// Running outside the development environment is what removes that inherited service: the host's
/// <c>appsettings.Development.json</c> is where it is declared.
/// </para>
/// </summary>
public class SingleServiceAuthProxyFactory : AuthProxyFactory
{
    /// <inheritdoc/>
    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        builder.UseEnvironment("Production");
        base.ConfigureWebHost(builder);
    }
}
