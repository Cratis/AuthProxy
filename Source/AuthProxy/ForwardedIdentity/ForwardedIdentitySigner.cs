// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Collections.Concurrent;
using System.Security.Cryptography;
using Microsoft.Extensions.Options;
using C = Cratis.AuthProxy.Configuration;

namespace Cratis.AuthProxy.ForwardedIdentity;

/// <summary>
/// Signs outbound requests with the configured EC P-256 key.
/// </summary>
/// <remarks>
/// The signing settings are read once, when the signer is created at startup, and never reloaded: a configuration
/// reload can neither switch signing off nor swap the key underneath running requests. Service audiences follow the
/// current configuration, like the routes they belong to. The imported key is kept in a small pool so a request
/// never pays for parsing PEM and no key instance is shared between concurrent signatures.
/// </remarks>
/// <param name="config">The auth proxy configuration.</param>
/// <param name="timeProvider">The clock assertions are issued by.</param>
/// <param name="logger">The logger.</param>
public sealed class ForwardedIdentitySigner(
    IOptionsMonitor<C.AuthProxy> config,
    TimeProvider timeProvider,
    ILogger<ForwardedIdentitySigner> logger) : IForwardedIdentitySigner, IDisposable
{
    readonly SigningSettings? _settings = SigningSettings.From(config.CurrentValue.ForwardingAttestation);
    readonly ConcurrentBag<ECDsa> _keys = [];
    readonly int _maximumPooledKeys = Math.Max(4, Environment.ProcessorCount * 2);

    /// <inheritdoc/>
    public bool IsEnabled => _settings is not null;

    /// <inheritdoc/>
    public string AudienceFor(string serviceName) => ForwardingAudiences.For(config.CurrentValue, serviceName);

    /// <inheritdoc/>
    public ForwardedIdentitySigningStatus Sign(HttpRequestMessage request, string audience)
    {
        if (_settings is null)
        {
            return ForwardedIdentitySigningStatus.NotConfigured;
        }

        if (string.IsNullOrWhiteSpace(_settings.PrivateKeyPem))
        {
            return NotSigned("no active signing key");
        }

        if (request.RequestUri is not { IsAbsoluteUri: true } uri)
        {
            return NotSigned("the request has no absolute address");
        }

        if (string.IsNullOrWhiteSpace(audience))
        {
            return NotSigned("no audience");
        }

        if (!ForwardedIdentityToken.TryCanonicalize(request.Headers, out var canonical, out var subject, out var tenant))
        {
            return NotSigned("an identity or tenant header is repeated or malformed");
        }

        try
        {
            var issuedAt = timeProvider.GetUtcNow().ToUnixTimeSeconds();
            var claims = new ForwardedIdentityClaims(
                _settings.Issuer,
                audience,
                issuedAt,
                issuedAt + _settings.LifetimeSeconds,
                ForwardedIdentityToken.CreateId(),
                request.Method.Method,
                uri.AbsolutePath,
                subject,
                tenant,
                ForwardedIdentityToken.Digest(canonical));

            var signingInput = ForwardedIdentityToken.SigningInput(_settings.KeyId, claims);
            var key = RentKey();
            string token;
            try
            {
                token = ForwardedIdentityToken.Complete(signingInput, key);
            }
            finally
            {
                ReturnKey(key);
            }

            request.Headers.Remove(Headers.ForwardedIdentity);
            return request.Headers.TryAddWithoutValidation(Headers.ForwardedIdentity, token)
                ? ForwardedIdentitySigningStatus.Attested
                : NotSigned("the assertion could not be attached");
        }
        catch (Exception exception)
        {
            // An outcome that cannot be classified is a failure: the request must not leave unsigned.
            logger.ForwardedIdentitySigningFailed(exception, _settings.KeyId);
            return ForwardedIdentitySigningStatus.Failed;
        }
    }

    /// <inheritdoc/>
    public void Dispose()
    {
        while (_keys.TryTake(out var key))
        {
            key.Dispose();
        }
    }

    ForwardedIdentitySigningStatus NotSigned(string reason)
    {
        logger.ForwardedIdentityNotSigned(reason);
        return ForwardedIdentitySigningStatus.Failed;
    }

    ECDsa RentKey()
    {
        if (_keys.TryTake(out var pooled))
        {
            return pooled;
        }

        var key = ECDsa.Create();
        try
        {
            key.ImportFromPem(_settings!.PrivateKeyPem);
            return key;
        }
        catch
        {
            key.Dispose();
            throw;
        }
    }

    void ReturnKey(ECDsa key)
    {
        if (_keys.Count < _maximumPooledKeys)
        {
            _keys.Add(key);
            return;
        }

        key.Dispose();
    }

    sealed record SigningSettings(string Issuer, string KeyId, string PrivateKeyPem, long LifetimeSeconds)
    {
        public static SigningSettings? From(C.ForwardingAttestation? attestation)
        {
            if (attestation is null)
            {
                return null;
            }

            var key = attestation.SigningKeys.FirstOrDefault(_ => string.Equals(_.KeyId, attestation.ActiveKeyId, StringComparison.Ordinal));
            var lifetime = attestation.Lifetime < C.ForwardingAttestation.MinimumLifetime
                ? C.ForwardingAttestation.MinimumLifetime
                : attestation.Lifetime > C.ForwardingAttestation.MaximumLifetime
                    ? C.ForwardingAttestation.MaximumLifetime
                    : attestation.Lifetime;

            return new(attestation.Issuer, attestation.ActiveKeyId, key?.PrivateKeyPem ?? string.Empty, (long)lifetime.TotalSeconds);
        }

        /// <inheritdoc/>
        public override string ToString() => $"{nameof(SigningSettings)} {{ {nameof(Issuer)} = {Issuer}, {nameof(KeyId)} = {KeyId}, {nameof(LifetimeSeconds)} = {LifetimeSeconds} }}";
    }
}
