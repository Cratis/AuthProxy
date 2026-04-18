// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using C = Cratis.AuthProxy.Configuration;

namespace Cratis.AuthProxy.Tenancy;

/// <summary>
/// Resolves the tenant source identifier from the request path using a named-group
/// regular expression. The named group must be called <c>sourceIdentifier</c>.
/// Configure the expression via the <c>pattern</c> option, e.g.:
/// <c>\/(?&lt;sourceIdentifier&gt;[\w]+)\/</c>.
/// </summary>
public class RouteSourceIdentifierStrategy : ISourceIdentifierStrategyTyped<RouteOptions>
{
    /// <inheritdoc/>
    public C.TenantSourceIdentifierResolverType Type => C.TenantSourceIdentifierResolverType.Route;

    /// <inheritdoc/>
    public bool TryResolveSourceIdentifier(HttpContext context, RouteOptions typedOptions, out string sourceIdentifier)
    {
        sourceIdentifier = string.Empty;

        var pattern = typedOptions.Pattern;
        if (string.IsNullOrWhiteSpace(pattern))
        {
            return false;
        }

        var path = context.Request.Path.Value ?? string.Empty;
        var match = System.Text.RegularExpressions.Regex.Match(path, pattern, System.Text.RegularExpressions.RegexOptions.IgnoreCase, TimeSpan.FromSeconds(1));
        if (!match.Success)
        {
            return false;
        }

        var group = match.Groups["sourceIdentifier"];
        if (!group.Success)
        {
            return false;
        }

        sourceIdentifier = group.Value;
        return !string.IsNullOrEmpty(sourceIdentifier);
    }
}
