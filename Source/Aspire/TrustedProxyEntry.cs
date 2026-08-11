// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Net;

namespace Cratis.AuthProxy.Aspire;

/// <summary>
/// Decides whether a declared trusted proxy is something AuthProxy will be able to resolve.
/// </summary>
/// <remarks>
/// Deliberately a copy of the rule AuthProxy applies in <c>TrustedProxyAddress</c> rather than a call into
/// it: this package is a hosting integration that an app host references on its own, without the proxy
/// assembly, the same reason <see cref="OidcProviderType"/> and <see cref="IdentityVerificationMode"/> are
/// declared here too. Keep the two in step — the value of checking here is that the answer matches what the
/// proxy will decide later.
/// </remarks>
static class TrustedProxyEntry
{
    /// <summary>
    /// Determines whether an entry names an address or a range.
    /// </summary>
    /// <param name="value">The declared entry.</param>
    /// <returns><see langword="true"/> when AuthProxy will resolve it; otherwise <see langword="false"/>.</returns>
    public static bool IsResolvable(string value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return false;
        }

        var entry = value.Trim();

        return entry.Contains('/', StringComparison.Ordinal)
            ? IPNetwork.TryParse(entry, out _)
            : IPAddress.TryParse(entry, out _);
    }
}
