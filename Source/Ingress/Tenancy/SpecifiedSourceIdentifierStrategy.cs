// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Text.Json.Nodes;

namespace Cratis.Ingress.Tenancy;

/// <summary>
/// Always resolves to the tenant ID specified in the <c>tenantId</c> option.
/// Used for single-tenant deployments.
/// </summary>
public class SpecifiedSourceIdentifierStrategy : ISourceIdentifierStrategy
{
    /// <inheritdoc/>
    public Configuration.TenantSourceIdentifierResolverType Type => Configuration.TenantSourceIdentifierResolverType.Specified;

    /// <inheritdoc/>
    public bool TryResolveSourceIdentifier(HttpContext context, JsonObject options, out string sourceIdentifier)
    {
        sourceIdentifier = options["tenantId"]?.GetValue<string>()
            ?? options["TenantId"]?.GetValue<string>()
            ?? options.FirstOrDefault(_ => _.Key.Equals("tenantId", StringComparison.OrdinalIgnoreCase)).Value?.GetValue<string>()
            ?? ResolveTenantIdFromConfiguration(context)
            ?? string.Empty;

        return !string.IsNullOrEmpty(sourceIdentifier);
    }

    static string? ResolveTenantIdFromConfiguration(HttpContext context)
    {
        if (context.RequestServices is null)
        {
            return null;
        }

        foreach (var resolution in context.RequestServices.GetService<IConfiguration>()?.GetSection("Ingress:TenantResolutions").GetChildren() ?? [])
        {
            if (!string.Equals(resolution["Strategy"], "Specified", StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            if (!string.IsNullOrWhiteSpace(resolution["Options:tenantId"]))
            {
                return resolution["Options:tenantId"];
            }

            if (!string.IsNullOrWhiteSpace(resolution["Options:TenantId"]))
            {
                return resolution["Options:TenantId"];
            }
        }

        return null;
    }
}
