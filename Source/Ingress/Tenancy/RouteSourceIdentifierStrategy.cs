// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using Cratis.Ingress.Configuration;

namespace Cratis.Ingress.Tenancy;

/// <summary>
/// Resolves the tenant source identifier from the request path using a named-group
/// regular expression. The named group must be called <c>sourceIdentifier</c>.
/// Configure the expression via the <c>regularExpression</c> option, e.g.:
/// <c>\/(?&lt;sourceIdentifier&gt;[\w]+)\/</c>.
/// </summary>
public class RouteSourceIdentifierStrategy : ISourceIdentifierStrategy
{
    /// <inheritdoc/>
    public TenantSourceIdentifierResolverType Type => TenantSourceIdentifierResolverType.Route;

    /// <inheritdoc/>
    public bool TryResolveSourceIdentifier(HttpContext context, JsonObject options, out string sourceIdentifier)
    {
        sourceIdentifier = string.Empty;

        var pattern = options["regularExpression"]?.GetValue<string>();
        if (string.IsNullOrWhiteSpace(pattern))
        {
            return false;
        }

        var path = context.Request.Path.Value ?? string.Empty;
        var match = Regex.Match(path, pattern, RegexOptions.IgnoreCase, TimeSpan.FromSeconds(1));
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
