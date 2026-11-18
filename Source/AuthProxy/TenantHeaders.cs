// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Net.Http.Headers;

namespace Cratis.AuthProxy;

/// <summary>
/// Makes sure a request leaves the proxy naming its tenant exactly once under each tenant header.
/// </summary>
/// <remarks>
/// A header sent twice is folded into one comma-separated value by anything reading the request as a flat dictionary, so
/// <c language="text">acme</c> sent twice reads <c language="text">acme,acme</c>. A backend that creates a tenant, or a Chronicle
/// namespace, the first time it sees a name then creates one called that. Several transforms and callers write the tenant, so
/// this is applied at the last boundary rather than trusting each of them to replace instead of append.
/// </remarks>
static class TenantHeaders
{
    static readonly string[] _names = [Headers.TenantId, Headers.LegacyTenantId];

    /// <summary>
    /// Leaves each tenant header with at most one value.
    /// </summary>
    /// <param name="headers">The headers of the request about to be sent.</param>
    /// <returns><see langword="true"/> when a repeated header was collapsed to its single value.</returns>
    /// <exception cref="TenantHeaderIsAmbiguous">A tenant header holds values that disagree, or a value that is itself a list.</exception>
    public static bool Sanitize(HttpRequestHeaders headers)
    {
        var collapsed = false;
        foreach (var name in _names)
        {
            if (!headers.TryGetValues(name, out var values))
            {
                continue;
            }

            var all = values.ToArray();
            if (all.Any(value => value.Contains(',')))
            {
                throw new TenantHeaderIsAmbiguous(name);
            }

            var distinct = all.Distinct(StringComparer.Ordinal).ToArray();
            if (distinct.Length > 1)
            {
                throw new TenantHeaderIsAmbiguous(name);
            }

            if (all.Length > 1)
            {
                headers.Remove(name);
                headers.TryAddWithoutValidation(name, distinct[0]);
                collapsed = true;
            }
        }

        return collapsed;
    }
}
