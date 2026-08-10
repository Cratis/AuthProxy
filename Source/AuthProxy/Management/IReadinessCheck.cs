// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Management;

/// <summary>
/// Defines something that answers whether this instance can serve traffic.
/// </summary>
/// <remarks>
/// Deliberately internal. AuthProxy ships as a sealed container image and only the Aspire package is
/// packable, so nothing outside this assembly could implement this; making it public would publish an
/// extension point nobody can reach and invite convention-based discovery into a codebase that registers
/// everything explicitly.
/// <para>
/// A readiness answer is about <em>local capability only</em>. An implementation must not call a backend,
/// an identity endpoint, a tenant-verification URL or an OIDC authority: readiness that depends on a
/// dependency turns that dependency's outage into this instance being pulled out of rotation, which
/// removes the proxy that would have served the error page.
/// </para>
/// </remarks>
internal interface IReadinessCheck
{
    /// <summary>
    /// Gets whether this instance can serve traffic, as of right now.
    /// </summary>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> for the request.</param>
    /// <returns><see langword="true"/> when it can; otherwise <see langword="false"/>.</returns>
    Task<bool> IsReady(CancellationToken cancellationToken);
}
