// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Security.given;

/// <summary>
/// The bearer-route deployment of <see cref="BearerRouteHarness"/>, signing what it forwards.
/// </summary>
/// <remarks>
/// Bearer routes are forwarded by their own forwarder rather than by the reverse-proxy routes, so they need their
/// own proof that the identity they forward is signed.
/// </remarks>
public class SignedBearerRouteHarness : BearerRouteHarness
{
    /// <summary>Gets the signing key, whose public half a backend would pin.</summary>
    public SignedForwarding Key { get; } = SignedForwarding.Generate();

    /// <inheritdoc/>
    protected override void AddSettings(IDictionary<string, string?> settings) => Key.AddTo(settings);
}
