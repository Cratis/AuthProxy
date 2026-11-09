// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.ForwardedIdentity;

/// <summary>A redacted diagnostic row for one outbound flow.</summary>
/// <param name="Flow">The outbound flow.</param>
/// <param name="ServiceName">The service, or null for the tenant list.</param>
/// <param name="IsSigned">Whether signing is configured.</param>
/// <param name="KeyId">The public key identifier.</param>
/// <param name="Audience">The receiving audience.</param>
public sealed record ForwardedIdentityFlowStatus(ForwardedIdentityFlow Flow, string? ServiceName, bool IsSigned, string? KeyId, string? Audience)
{
    /// <summary>Gets the configured wire version, or null when envelope signing is not configured.</summary>
    public string? Version { get; init; }

    /// <summary>Gets the current producer readiness, distinct from whether signing is configured.</summary>
    public string State => Version == "v2" ? "refusing: no context producer" : IsAttested ? "attested" : IsSigned ? "signed" : "not signed";

    /// <summary>Gets whether this flow uses a per-call attestation rather than the forwarded-identity envelope.</summary>
    public bool IsAttested { get; init; }

    /// <summary>Gets the configured transport protection for this flow.</summary>
    public BackendHops.BackendHopTransport Transport { get; init; }
}
