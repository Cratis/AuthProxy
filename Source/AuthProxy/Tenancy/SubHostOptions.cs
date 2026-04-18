// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Tenancy;

/// <summary>
/// Options for the <see cref="SubHostSourceIdentifierStrategy"/>.
/// </summary>
public record SubHostOptions
{
    /// <summary>
    /// Gets the parent host used to extract the tenant from the request host.
    /// For example, with <c>ParentHost</c> set to <c>example.com</c>,
    /// a host of <c>acme.example.com</c> resolves the tenant ID <c>acme</c>.
    /// </summary>
    public string? ParentHost { get; init; }

    /// <summary>
    /// Gets an optional URL template used to verify resolved subhost tenant IDs.
    /// Use <c>{tenantId}</c> as a placeholder.
    /// </summary>
    public string? VerificationUrlTemplate { get; init; }
}
