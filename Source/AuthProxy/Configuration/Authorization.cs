// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Configuration;

/// <summary>
/// Represents the first-gate authorization configuration: what an authenticated caller must carry before
/// the proxy will let the request through to a service at all.
/// </summary>
/// <remarks>
/// Authentication answers <em>who</em> a caller is; on a public host that is not the same as deciding
/// whether they may be here. Without this, any account the configured identity provider is willing to
/// authenticate — which for a public provider such as GitHub is every account on the internet — completes
/// sign-in and reaches the application. Declaring requirements here turns the proxy into the first gate,
/// so the application is never asked to answer for a caller who should not have arrived.
/// <para>
/// Declared at the root it applies to every service; declared on a <see cref="Service"/> it applies to
/// that service in addition to the root's. Nothing declared anywhere is the default, and it leaves the
/// proxy behaving exactly as it did before this existed.
/// </para>
/// </remarks>
public class Authorization
{
    /// <summary>
    /// The configuration section key for the global authorization settings.
    /// </summary>
    public const string SectionKey = $"{AuthProxy.SectionKey}:Authorization";

    /// <summary>
    /// Gets or sets the claim requirements an authenticated caller must satisfy.
    /// </summary>
    /// <remarks>
    /// <strong>Every</strong> requirement must hold — the list is an <em>and</em>. Within one requirement,
    /// any of its listed values will do — <see cref="ClaimRequirement.AnyOf"/> is an <em>or</em>. Express
    /// "in this organization <em>and</em> on this team" as two requirements, and "in either of these two
    /// organizations" as one requirement with two values.
    /// </remarks>
    public IList<ClaimRequirement> RequiredClaims { get; set; } = [];

    /// <summary>
    /// Gets a value indicating whether anything is required at all.
    /// </summary>
    public bool HasRequirements => RequiredClaims.Count > 0;
}
