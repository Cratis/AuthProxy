// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.ReverseProxy;

/// <summary>
/// The lower-cased identity of a configured service, used in route ids, cluster ids and metadata.
/// </summary>
/// <param name="Value">The lower-cased service key.</param>
readonly record struct ServiceKey(string Value)
{
    /// <summary>
    /// Derives the key of a configured service name.
    /// </summary>
    /// <param name="serviceName">The configured service name.</param>
    /// <returns>The invariant lower-cased key.</returns>
    public static ServiceKey From(string serviceName) => new(serviceName.ToLowerInvariant());

    /// <summary>
    /// Unwraps a service key to its text.
    /// </summary>
    /// <param name="key">The service key.</param>
    public static implicit operator string(ServiceKey key) => key.Value;

    /// <inheritdoc/>
    public override string ToString() => Value;
}
