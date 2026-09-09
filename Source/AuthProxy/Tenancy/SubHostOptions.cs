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
    /// For example, with <c language="text">ParentHost</c> set to <c language="text">example.com</c>,
    /// a host of <c language="text">acme.example.com</c> resolves the tenant ID <c language="text">acme</c>.
    /// </summary>
    public string? ParentHost { get; init; }

    /// <summary>
    /// Gets an optional URL template used to verify resolved subhost tenant IDs.
    /// Use <c language="text">{tenantId}</c> as a placeholder.
    /// </summary>
    public string? VerificationUrlTemplate { get; init; }
}
