// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.BackendHops;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace Cratis.AuthProxy.ForwardedIdentity;

/// <summary>Registers signing policy and redacted per-flow startup diagnostics.</summary>
public static class ForwardedIdentityServiceCollectionExtensions
{
    /// <summary>The redirect-disabled client used only by signed internal flows.</summary>
    internal const string HttpClientName = "ForwardedIdentitySigned";

    /// <summary>Adds the v1 signing service and signed back-channel transport.</summary>
    /// <param name="builder">The application builder.</param>
    public static void AddForwardedIdentitySigning(this WebApplicationBuilder builder)
    {
        builder.Services.AddBackendTls();
        builder.Services.TryAddSingleton(TimeProvider.System);
        builder.Services.TryAddSingleton<IForwardedIdentitySigner, ForwardedIdentitySigner>();
        builder.Services.TryAddEnumerable(ServiceDescriptor.Singleton<IHostedService, ForwardedIdentitySigningStartupReport>());

        builder.Services.AddHttpClient(HttpClientName).ConfigurePrimaryHttpMessageHandler(services => services.GetRequiredService<BackendTlsHttpClientPolicy>().CreateHandler());
    }
}
