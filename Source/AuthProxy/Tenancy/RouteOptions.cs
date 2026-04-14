// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Tenancy;

/// <summary>
/// Options for the <see cref="RouteSourceIdentifierStrategy"/> that resolves tenant ID from a URL path pattern.
/// </summary>
public record RouteOptions
{
    /// <summary>Gets the regular expression pattern to match against the request path. The pattern must contain a named group called 'sourceIdentifier'.</summary>
    public string? Pattern { get; init; }
}
