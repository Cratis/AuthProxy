// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Security.Cryptography;
using Microsoft.Extensions.Options;
using C = Cratis.AuthProxy.Configuration;

namespace Cratis.AuthProxy.BackendHops;

/// <summary>
/// Atomically publishes valid certificate snapshots while preserving the last good material.
/// </summary>
/// <param name="config">The deployment configuration.</param>
/// <param name="timeProvider">The certificate validity clock.</param>
/// <param name="logger">The redacted material logger.</param>
internal sealed class BackendTlsMaterialSource(IOptionsMonitor<C.AuthProxy> config, TimeProvider timeProvider, ILogger<BackendTlsMaterialSource> logger) : IBackendTlsMaterialSource
{
    readonly object _gate = new();
    volatile BackendTlsMaterial? _current;

    /// <inheritdoc/>
    public BackendTlsMaterial Current
    {
        get
        {
            if (_current is { } current) return current;
            lock (_gate)
            {
                if (_current is null)
                {
                    if (!BackendTlsMaterial.TryLoad(config.CurrentValue.BackendTls, timeProvider.GetUtcNow(), out var loaded, out var problem))
                    {
                        throw new OptionsValidationException(C.AuthProxy.SectionKey, typeof(C.AuthProxy), [problem!]);
                    }
                    _current = loaded!;
                }
                return _current;
            }
        }
    }

    /// <inheritdoc/>
    public bool TryReload()
    {
        lock (_gate)
        {
            var current = Current;
            if (current.ClientCertificate is { } certificate && timeProvider.GetUtcNow().UtcDateTime > certificate.NotAfter.ToUniversalTime()) logger.ClientExpired();
            if (!BackendTlsMaterial.TryLoad(config.CurrentValue.BackendTls, timeProvider.GetUtcNow(), out var loaded, out var problem))
            {
                logger.ReloadRefused(problem!);
                return false;
            }

            if (loaded!.Fingerprint == current.Fingerprint)
            {
                loaded.ClientCertificate?.Dispose();
                foreach (var anchor in loaded.TrustAnchors) anchor.Dispose();
                return false;
            }

            // Handshakes may still hold the previous snapshot. Let its certificate handles be finalized
            // only after those readers release it rather than disposing underneath an active handshake.
            _current = loaded;
            logger.MaterialReloaded(loaded.ClientCertificate?.Subject, loaded.ClientCertificate?.GetCertHashString(HashAlgorithmName.SHA256), loaded.ClientCertificate?.NotAfter, loaded.TrustAnchors.Count);
            return true;
        }
    }
}
