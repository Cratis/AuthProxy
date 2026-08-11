// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

namespace Cratis.AuthProxy.for_IngressExtensions.given;

/// <summary>
/// An application configured through <c>AddIngressConfiguration</c> from a supplied ingress section.
/// </summary>
/// <remarks>
/// Built from configuration keys rather than from an options object, because the keys are the surface a
/// deployment actually writes — through environment variables, a mounted appsettings file, or the Aspire
/// builders — and binding them is the part that can silently be wrong.
/// </remarks>
public class an_ingress_configuration : Specification
{
    protected ServiceProvider _serviceProvider;

    protected virtual IDictionary<string, string?> IngressSettings => new Dictionary<string, string?>();

    void Establish()
    {
        var builder = WebApplication.CreateBuilder();
        builder.Configuration.AddInMemoryCollection(IngressSettings);
        builder.AddIngressConfiguration();

        _serviceProvider = builder.Services.BuildServiceProvider();
    }

    void Destroy() => _serviceProvider.Dispose();
}
