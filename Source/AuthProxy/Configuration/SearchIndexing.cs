// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Configuration;

/// <summary>
/// Configures deployment-wide requests to search engines not to index proxied applications.
/// </summary>
public class SearchIndexing
{
    /// <summary>
    /// Gets or sets a value indicating whether to serve a disallow-all robots file and add a noindex
    /// response header. Defaults to false; an existing upstream header is preserved.
    /// </summary>
    public bool Exclude { get; set; }
}
