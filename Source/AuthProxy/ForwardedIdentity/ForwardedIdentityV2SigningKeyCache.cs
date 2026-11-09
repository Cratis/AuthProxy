// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Security.Cryptography;
using System.Text;
using Microsoft.Extensions.Options;
using C = Cratis.AuthProxy.Configuration;

namespace Cratis.AuthProxy.ForwardedIdentity;

/// <summary>Owns one serialized-use signing handle per configured key until configuration reload or shutdown.</summary>
internal sealed class ForwardedIdentityV2SigningKeyCache : IDisposable
{
    readonly Lock _gate = new();
    readonly Dictionary<string, ECDsa> _keys = new(StringComparer.Ordinal);
    readonly IDisposable? _subscription;
    bool _disposed;

    /// <summary>Initializes a cache whose handles are retired on configuration reload.</summary>
    /// <param name="config">The live gateway configuration.</param>
    internal ForwardedIdentityV2SigningKeyCache(IOptionsMonitor<C.AuthProxy> config) => _subscription = config.OnChange((_, _) => Clear());

    /// <summary>Gets the number of live handles, without exposing key material.</summary>
    internal int Count
    {
        get
        {
            lock (_gate) return _keys.Count;
        }
    }

    /// <inheritdoc/>
    public void Dispose()
    {
        _subscription?.Dispose();
        lock (_gate)
        {
            _disposed = true;
            Clear();
        }
    }

    /// <summary>Signs with a cached validated handle; no decoded private DER survives import.</summary>
    /// <param name="settings">The current version-pinned configuration.</param>
    /// <param name="timestamp">The issuance timestamp.</param>
    /// <param name="nonce">The fresh nonce.</param>
    /// <param name="canonical">The bounded canonical input.</param>
    /// <param name="proof">The resulting envelope.</param>
    /// <returns>Whether the key configuration is usable.</returns>
    internal bool TrySign(C.ForwardedIdentitySigning settings, string timestamp, string nonce, byte[] canonical, out string? proof)
    {
        proof = null;
        if (!ForwardedIdentityV2SigningKey.IsValidSettings(settings)) return false;
        var fingerprint = Fingerprint(settings.PrivateKeyPkcs8Base64);
        lock (_gate)
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            if (!_keys.TryGetValue(fingerprint, out var signer))
            {
                if (!ForwardedIdentityV2SigningKey.TryOpen(settings, out signer)) return false;
                _keys.Add(fingerprint, signer!);
            }
            proof = ForwardedIdentityV2Envelope.Sign(signer!, settings.KeyId, timestamp, nonce, canonical);
            return true;
        }
    }

    static string Fingerprint(string material)
    {
        var bytes = Encoding.UTF8.GetBytes(material);
        try
        {
            return Convert.ToHexString(SHA256.HashData(bytes));
        }
        finally
        {
            CryptographicOperations.ZeroMemory(bytes);
        }
    }

    void Clear()
    {
        lock (_gate)
        {
            foreach (var key in _keys.Values) key.Dispose();
            _keys.Clear();
        }
    }
}
