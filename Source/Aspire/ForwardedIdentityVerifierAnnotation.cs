// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Aspire;

/// <summary>Tracks the audience and verifier key slots shared by a backend's pairings.</summary>
internal sealed class ForwardedIdentityVerifierAnnotation : IResourceAnnotation
{
    /// <summary>Gets or sets the audience all pairings must use.</summary>
    public string? Audience { get; set; }

    /// <summary>Gets the key identifiers in their verifier slot order.</summary>
    public List<string> KeyIds { get; } = [];
}
