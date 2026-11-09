// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Globalization;
using Cratis.AuthProxy.Authentication;
using Microsoft.Extensions.Options;
using C = Cratis.AuthProxy.Configuration;

namespace Cratis.AuthProxy.ForwardedIdentity;

/// <summary>Produces version-pinned Arc proofs using the actual outbound flow's current settings.</summary>
/// <param name="config">The current gateway configuration.</param>
/// <param name="time">The issuance clock.</param>
/// <param name="logger">The redacted signing logger.</param>
/// <param name="httpContextAccessor">The current authenticated browser request, when available.</param>
public sealed class ForwardedIdentitySigner(IOptionsMonitor<C.AuthProxy> config, TimeProvider time, ILogger<ForwardedIdentitySigner> logger, IHttpContextAccessor? httpContextAccessor = null) : IForwardedIdentitySigner, IDisposable
{
    readonly ForwardedIdentityV2SigningKeyCache _v2Keys = new(config);
    int _missingAccessorReported;

    /// <summary>Creates a signer without ambient browser request access.</summary>
    /// <param name="config">The current gateway configuration.</param>
    /// <param name="time">The issuance clock.</param>
    /// <param name="logger">The redacted signing logger.</param>
    public ForwardedIdentitySigner(IOptionsMonitor<C.AuthProxy> config, TimeProvider time, ILogger<ForwardedIdentitySigner> logger)
        : this(config, time, logger, null)
    {
    }

    /// <inheritdoc/>
    public ForwardedIdentitySigningOutcome Sign(HttpRequestMessage request, ForwardedIdentitySigningTarget target)
    {
        request.Headers.Remove(Headers.ForwardedIdentitySignature);
        var settings = Settings(target);
        if (settings is null) return ForwardedIdentitySigningOutcome.NotConfigured;
        if (settings.Version != "v1") return SignV2(request, target, settings);
        if (!ForwardedIdentityCanonicalInput.IsIdentityBearing(request)) return ForwardedIdentitySigningOutcome.NotIdentityBearing;
        if (!ForwardedIdentitySigningKey.TryCreate(settings, out var key, out _))
        {
            logger.ConfigurationRefused(target.Flow, target.ServiceName);
            return ForwardedIdentitySigningOutcome.Refused;
        }
        try
        {
            var timestamp = time.GetUtcNow().ToUnixTimeSeconds().ToString(CultureInfo.InvariantCulture);
            var nonce = ForwardedIdentityEnvelope.NewNonce();
            if (!ForwardedIdentityCanonicalInput.TryCreate(request, key!.Audience, key.KeyId, timestamp, nonce, out var canonical, out var refusal))
            {
                logger.SigningRefused(target.Flow, target.ServiceName, key.KeyId, refusal);
                return ForwardedIdentitySigningOutcome.Refused;
            }
            request.Headers.TryAddWithoutValidation(Headers.ForwardedIdentitySignature, ForwardedIdentityEnvelope.Format(key.KeyId, timestamp, nonce, ForwardedIdentityEnvelope.Mac(key.Secret.Span, canonical)));
            logger.Signed(target.Flow, target.ServiceName, key.KeyId);
            return ForwardedIdentitySigningOutcome.SignatureCreated;
        }
        catch (Exception)
        {
            logger.SigningFailed(target.Flow, target.ServiceName, key!.KeyId);
            return ForwardedIdentitySigningOutcome.Refused;
        }
    }

    /// <inheritdoc/>
    public void Dispose() => _v2Keys.Dispose();

    static bool IsCurrentBrowserContext(ForwardedIdentityTrustedContext? context, DateTimeOffset now)
    {
        if (context is not { CredentialKind: "browser-session", SenderBinding: "none", Actor: null, GrantId: null, Bearer: null }) return false;
        return context.SnapshotExpiresUtc is not { } expires || now < expires;
    }

    static bool TryApply(HttpRequestMessage request, ForwardedIdentityTrustedContext context) => ForwardedIdentityTenantHeader.Apply(request, context.TenantHeader)
        && ForwardedIdentityV2ContextHeaders.TryApply(request, context);

    ForwardedIdentitySigningOutcome SignV2(HttpRequestMessage request, ForwardedIdentitySigningTarget target, C.ForwardedIdentitySigning settings)
    {
        WarnIfMissingAccessor();
        if (!ForwardedIdentityV2SigningKey.IsValidSettings(settings))
        {
            logger.ConfigurationRefused(target.Flow, target.ServiceName);
            return ForwardedIdentitySigningOutcome.Refused;
        }
        try
        {
            var input = PrepareV2(request, settings);
            if (input is null)
            {
                logger.SigningFailed(target.Flow, target.ServiceName, settings.KeyId);
                return ForwardedIdentitySigningOutcome.Refused;
            }
            if (!_v2Keys.TrySign(settings, input.Timestamp, input.Nonce, input.Canonical, out var proof))
            {
                logger.ConfigurationRefused(target.Flow, target.ServiceName);
                return ForwardedIdentitySigningOutcome.Refused;
            }
            request.Headers.TryAddWithoutValidation(Headers.ForwardedIdentitySignature, proof);
            logger.Signed(target.Flow, target.ServiceName, settings.KeyId);
            return ForwardedIdentitySigningOutcome.SignatureCreated;
        }
        catch (Exception)
        {
            logger.SigningFailed(target.Flow, target.ServiceName, settings.KeyId);
            return ForwardedIdentitySigningOutcome.Refused;
        }
    }

    SigningInput? PrepareV2(HttpRequestMessage request, C.ForwardedIdentitySigning settings)
    {
        var now = time.GetUtcNow();
        var timestamp = now.ToUnixTimeSeconds().ToString(CultureInfo.InvariantCulture);
        var nonce = ForwardedIdentityV2Envelope.Encode(System.Security.Cryptography.RandomNumberGenerator.GetBytes(16));
        var context = TrustedContext(request, settings.TenantHeader);
        if (!IsCurrentBrowserContext(context, now)) return null;
        if (!TryApply(request, context!)) return null;
        if (!ForwardedIdentityV2CanonicalInput.TryCreate(request, context!, settings.Audience, settings.KeyId, timestamp, nonce, out var canonical)) return null;
        return new(timestamp, nonce, canonical);
    }

    void WarnIfMissingAccessor()
    {
        if (httpContextAccessor is null && Interlocked.Exchange(ref _missingAccessorReported, 1) == 0) logger.MissingHttpContextAccessor();
    }

    ForwardedIdentityTrustedContext? TrustedContext(HttpRequestMessage request, string tenantHeader)
    {
        if (!request.Options.TryGetValue(ForwardedIdentityTrustedContext.OptionsKey, out var context)) context = BrowserSessionEvidence.For(httpContextAccessor?.HttpContext);
        return context is null ? null : context with { TenantHeader = tenantHeader };
    }

    C.ForwardedIdentitySigning? Settings(ForwardedIdentitySigningTarget target)
    {
        var configuration = config.CurrentValue;
        if (target.Flow == ForwardedIdentityFlow.TenantList)
        {
            return TenantSelectionMiddleware.TryGetSelectionOptions(configuration, out var selection) ? selection.ForwardedIdentity : null;
        }
        return target.ServiceName is not null && configuration.Services.TryGetValue(target.ServiceName, out var service) ? service.ForwardedIdentity : null;
    }

    sealed record SigningInput(string Timestamp, string Nonce, byte[] Canonical);
}
