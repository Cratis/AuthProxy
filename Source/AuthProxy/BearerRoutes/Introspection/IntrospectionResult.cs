// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.BearerRoutes.Introspection;

/// <summary>The narrowed verdict and optional authoritative grant evidence from introspection.</summary>
/// <param name="Verdict">The existing activity verdict.</param>
/// <param name="Credential">The endpoint's grant identity, never derived from token claims.</param>
/// <param name="ExpiresAt">The endpoint's absolute expiration, when supplied.</param>
public sealed record IntrospectionResult(IntrospectionVerdict Verdict, IntrospectionCredential? Credential = null, DateTimeOffset? ExpiresAt = null)
{
    /// <summary>Gets the original absolute freshness deadline of active grant evidence.</summary>
    public DateTimeOffset? ValidUntil { get; init; }

    /// <inheritdoc/>
    public override string ToString() => nameof(IntrospectionResult);
}
