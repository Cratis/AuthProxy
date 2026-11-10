// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Configuration;

/// <summary>Configures opt-in resource-server DPoP verification.</summary>
public sealed class Dpop
{
    /// <summary>The configuration section.</summary>
    public const string SectionKey = $"{AuthProxy.SectionKey}:Dpop";

    /// <summary>Gets or sets the fleet-shared replay store.</summary>
    public DpopReplay ReplayStore { get; set; } = new();

    /// <summary>Gets or sets whether resource-server nonces are required. Defaults to false.</summary>
    public bool NonceRequired { get; set; }
}
