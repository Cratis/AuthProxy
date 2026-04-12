// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.Ingress.Configuration;
using Microsoft.Extensions.Configuration;

namespace Cratis.Ingress.Tenancy;

/// <summary>
/// Always resolves to the tenant ID specified in the <c>tenantId</c> option.
/// Used for single-tenant deployments.
/// </summary>
public class SpecifiedSourceIdentifierStrategy : ISourceIdentifierStrategyTyped<SpecifiedOptions>
{
        /// <inheritdoc/>
    public TenantSourceIdentifierResolverType Type => TenantSourceIdentifierResolverType.Specified;

        /// <inheritdoc/>
    public bool TryResolveSourceIdentifier(HttpContext context, SpecifiedOptions options, out string sourceIdentifier)
          {
        sourceIdentifier = options.TenantId
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
