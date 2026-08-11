// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Security.given;

/// <summary>
/// An <see cref="IHttpClientFactory"/> that records how often AuthProxy asked it for a client.
/// </summary>
/// <remarks>
/// "The health endpoints call nothing" is a claim about work that does <em>not</em> happen, and the only
/// honest way to assert it is to count the one thing every outbound call in AuthProxy has to obtain first.
/// An implementation that quietly verified a tenant, resolved identity details or reached an OIDC authority
/// on the way to answering a probe would move this counter.
/// </remarks>
public sealed class CountingHttpClientFactory : IHttpClientFactory
{
    int _created;

    /// <summary>
    /// Gets how many clients have been handed out.
    /// </summary>
    public int Created => Volatile.Read(ref _created);

    /// <inheritdoc/>
    public HttpClient CreateClient(string name)
    {
        Interlocked.Increment(ref _created);

        return new HttpClient();
    }
}
