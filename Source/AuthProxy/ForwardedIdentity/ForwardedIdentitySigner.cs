// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Globalization;
using Microsoft.Extensions.Options;
using C = Cratis.AuthProxy.Configuration;

namespace Cratis.AuthProxy.ForwardedIdentity;

/// <summary>Produces Arc v1 proofs using the actual outbound flow's current settings.</summary>
/// <param name="config">The current gateway configuration.</param>
/// <param name="time">The issuance clock.</param>
/// <param name="logger">The redacted signing logger.</param>
public sealed class ForwardedIdentitySigner(IOptionsMonitor<C.AuthProxy> config, TimeProvider time, ILogger<ForwardedIdentitySigner> logger) : IForwardedIdentitySigner
{
    /// <inheritdoc/>
    public ForwardedIdentitySigningOutcome Sign(HttpRequestMessage request, ForwardedIdentitySigningTarget target)
    {
        request.Headers.Remove(Headers.ForwardedIdentitySignature);
        var settings = Settings(target);
        if (settings is null) return ForwardedIdentitySigningOutcome.NotConfigured;
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

    C.ForwardedIdentitySigning? Settings(ForwardedIdentitySigningTarget target)
    {
        var configuration = config.CurrentValue;
        if (target.Flow == ForwardedIdentityFlow.TenantList)
        {
            return TenantSelectionMiddleware.TryGetSelectionOptions(configuration, out var selection) ? selection.ForwardedIdentity : null;
        }
        return target.ServiceName is not null && configuration.Services.TryGetValue(target.ServiceName, out var service) ? service.ForwardedIdentity : null;
    }
}
