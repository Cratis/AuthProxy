// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Identity;

/// <summary>
/// Represents the versioned structured payload sealed into an identity authorization cookie.
/// </summary>
internal sealed record IdentityAuthorizationRecord
{
    /// <summary>
    /// Gets the current structured payload version.
    /// </summary>
    public const int CurrentVersion = 2;

    /// <summary>
    /// Gets or initializes the payload version.
    /// </summary>
    public int Version { get; init; }

    /// <summary>
    /// Gets or initializes the expiry as Unix time seconds.
    /// </summary>
    public long ExpiresAt { get; init; }

    /// <summary>
    /// Gets or initializes the tenant identifier.
    /// </summary>
    public string TenantId { get; init; } = string.Empty;

    /// <summary>
    /// Gets or initializes the validated account binding.
    /// </summary>
    public IdentityAccountBinding? Account { get; init; }
}
