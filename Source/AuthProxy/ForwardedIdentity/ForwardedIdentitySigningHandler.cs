// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.ForwardedIdentity;

/// <summary>Signs each final outbound YARP message immediately before transport.</summary>
/// <param name="signer">The per-flow v1 signer.</param>
/// <param name="logger">The redacted signing logger.</param>
internal sealed class ForwardedIdentitySigningHandler(IForwardedIdentitySigner signer, ILogger logger) : DelegatingHandler
{
    /// <inheritdoc/>
    protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        if (request.Options.TryGetValue(AnonymousPaths.ForwardWithoutIdentity, out var anonymous) && anonymous)
        {
            // Last outbound boundary: remove caller-supplied and proxy-generated identity alike.
            SpoofableHeaders.Strip(request.Headers);
            request.Headers.Remove("Authorization");
        }
        else if (!request.Options.TryGetValue(ForwardedIdentitySigningTarget.OptionsKey, out var target))
        {
            request.Headers.Remove(Headers.ForwardedIdentitySignature);
        }
        else if (signer.Sign(request, target) == ForwardedIdentitySigningOutcome.Refused)
        {
            logger.SigningRefused();
            throw new ForwardedIdentityCouldNotBeSigned();
        }
        return base.SendAsync(request, cancellationToken);
    }
}
