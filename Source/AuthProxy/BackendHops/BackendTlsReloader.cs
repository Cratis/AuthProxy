// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.Extensions.Options;
using C = Cratis.AuthProxy.Configuration;

namespace Cratis.AuthProxy.BackendHops;

/// <summary>
/// Polls files, including Kubernetes secret symlink replacements, without rebuilding handlers.
/// </summary>
/// <param name="config">The deployment configuration.</param>
/// <param name="source">The atomic material source.</param>
/// <param name="timeProvider">The polling clock.</param>
internal sealed class BackendTlsReloader(IOptionsMonitor<C.AuthProxy> config, IBackendTlsMaterialSource source, TimeProvider timeProvider) : BackgroundService
{
    /// <inheritdoc/>
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        var settings = config.CurrentValue.BackendTls;
        if (settings.ClientCertificate is null && string.IsNullOrEmpty(settings.TrustedCertificateAuthoritiesPath)) return;
        using var timer = new PeriodicTimer(settings.ReloadInterval, timeProvider);
        while (await timer.WaitForNextTickAsync(stoppingToken))
        {
            source.TryReload();
            timer.Period = config.CurrentValue.BackendTls.ReloadInterval;
        }
    }
}
