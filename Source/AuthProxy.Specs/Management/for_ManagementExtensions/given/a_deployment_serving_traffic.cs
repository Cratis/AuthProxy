// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

namespace Cratis.AuthProxy.Management.for_ManagementExtensions.given;

/// <summary>
/// An AuthProxy already told to serve traffic on the port the container images publish, before anything is
/// asked of the management listener.
/// </summary>
public class a_deployment_serving_traffic : Specification
{
    protected const string PublicUrl = "http://+:8080";
    protected WebApplicationBuilder _builder;

    protected virtual IDictionary<string, string?> ManagementSettings => new Dictionary<string, string?>();

    void Establish()
    {
        _builder = WebApplication.CreateBuilder();
        _builder.WebHost.UseUrls(PublicUrl);
        _builder.Configuration.AddInMemoryCollection(ManagementSettings);
    }

    /// <summary>
    /// Gets the addresses the host would be started with.
    /// </summary>
    protected IReadOnlyList<string> DeclaredAddresses =>
        [.. (_builder.Configuration[WebHostDefaults.ServerUrlsKey] ?? string.Empty).Split(';', StringSplitOptions.RemoveEmptyEntries)];

    /// <summary>
    /// Builds the services the registration produced, without building the host.
    /// </summary>
    /// <returns>The service provider.</returns>
    protected ServiceProvider Services() => _builder.Services.BuildServiceProvider();
}
