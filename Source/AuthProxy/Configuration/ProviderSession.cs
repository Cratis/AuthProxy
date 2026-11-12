// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Configuration;

/// <summary>Represents optional shorten-only browser-session settings for one provider.</summary>
public class ProviderSession
{
    /// <summary>Gets or sets the ticket lifetime. Null inherits the global lifetime; a value must be positive and no longer than that lifetime.</summary>
    public TimeSpan? Lifetime { get; set; }

    /// <summary>Gets or sets whether sliding expiration is allowed. Null inherits; false disables it; true cannot enable globally disabled sliding.</summary>
    public bool? SlidingExpiration { get; set; }
}
