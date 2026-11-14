// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.BearerRoutes.Introspection;

/// <summary>The authoritative grant identity returned by the issuer's introspection endpoint.</summary>
/// <param name="CredentialId">The canonical grant UUID, never derived from token claims.</param>
/// <param name="Epoch">The endpoint's cache epoch, when present.</param>
public sealed record IntrospectionCredential(string CredentialId, string? Epoch)
{
    /// <inheritdoc/>
    public override string ToString() => nameof(IntrospectionCredential);
}
