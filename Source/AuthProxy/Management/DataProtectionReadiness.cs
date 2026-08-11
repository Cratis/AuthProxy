// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Globalization;
using Microsoft.AspNetCore.DataProtection;

namespace Cratis.AuthProxy.Management;

/// <summary>
/// Answers readiness by round-tripping a value through Data Protection.
/// </summary>
/// <param name="dataProtection">The <see cref="IDataProtectionProvider"/> the deployment was configured with.</param>
/// <param name="logger">The <see cref="ILogger"/> that records why an instance is not ready.</param>
/// <remarks>
/// The key ring is what encrypts the authentication cookie and the AuthProxy-issued client-credentials
/// tokens, so an instance whose key ring will not initialize cannot serve a single authenticated request —
/// yet it accepts sockets perfectly well, which is exactly why a TCP probe reports it healthy and sends it
/// traffic. A <c>Protect</c>/<c>Unprotect</c> round-trip is the only thing that forces initialization and
/// proves it against the configured <c>DataProtectionKeysPath</c> rather than against a cached opinion.
/// <para>
/// It is re-run on every call, and no answer is remembered. A key ring that becomes unusable — a volume
/// unmounted, a permission revoked — has to change the answer, and a cached "ready" would keep an instance
/// in rotation for as long as the cache lived.
/// </para>
/// <para>
/// Failure is logged and never returned. The reason names a filesystem path, a key identifier or an
/// exception type, all of which describe the deployment to anyone who can reach the endpoint.
/// </para>
/// </remarks>
internal sealed class DataProtectionReadiness(IDataProtectionProvider dataProtection, ILogger<DataProtectionReadiness> logger) : IReadinessCheck
{
    /// <summary>
    /// The purpose the readiness probe protects under. Its own purpose, so a probe can never produce or
    /// accept a payload that anything else in AuthProxy would.
    /// </summary>
    internal const string Purpose = "Cratis.AuthProxy.Management.Readiness";

    /// <inheritdoc/>
    public Task<bool> IsReady(CancellationToken cancellationToken)
    {
        try
        {
            var protector = dataProtection.CreateProtector(Purpose);
            var probe = Guid.NewGuid().ToString("N", CultureInfo.InvariantCulture);

            return Task.FromResult(string.Equals(protector.Unprotect(protector.Protect(probe)), probe, StringComparison.Ordinal));
        }
        catch (Exception exception)
        {
            logger.KeyRingUnavailable(exception);

            return Task.FromResult(false);
        }
    }
}
