// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.Extensions.Options;
using C = Cratis.AuthProxy.Configuration;

namespace Cratis.AuthProxy.Authentication;

/// <summary>Warns when a general JWT deployment has not opted into tenant binding.</summary>
/// <param name="configuration">The deployment configuration.</param>
/// <param name="options">The authentication settings.</param>
/// <param name="logger">The logger.</param>
internal sealed partial class ExternalTokenTenantBindingStartupReport(
    IConfiguration configuration,
    IOptionsMonitor<C.Authentication> options,
    ILogger<ExternalTokenTenantBindingStartupReport> logger) : IHostedService
{
    /// <inheritdoc/>
    public Task StartAsync(CancellationToken cancellationToken)
    {
        if (configuration.GetSection($"{C.Authentication.SectionKey}:JwtBearer").Exists()
            && !options.CurrentValue.ExternalTokenTenantBinding.Require)
        {
            WarnTenantBindingDisabled(logger);
        }

        return Task.CompletedTask;
    }

    /// <inheritdoc/>
    public Task StopAsync(CancellationToken cancellationToken) => Task.CompletedTask;

    [LoggerMessage(LogLevel.Warning, "JWT Bearer is configured without external token tenant binding. Tokens are not constrained to a credential tenant. Enable Authentication:ExternalTokenTenantBinding:Require for multi-tenant deployments.")]
    static partial void WarnTenantBindingDisabled(ILogger logger);
}
