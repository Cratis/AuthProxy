// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Aspire;

public static partial class AuthProxyExtensions
{
    /// <summary>
    /// Requires HTTPS for every identity-bearing destination, including unsigned backends and callbacks.
    /// AuthProxy validates the targets at startup. Select HTTPS endpoints when registering resources.
    /// </summary>
    /// <typeparam name="T">The resource type.</typeparam>
    /// <param name="builder">The resource builder.</param>
    /// <returns>The same resource builder for chaining.</returns>
    public static IResourceBuilder<T> WithRequiredTlsOnIdentityHops<T>(this IResourceBuilder<T> builder)
        where T : IResourceWithEnvironment =>
        builder.WithEnvironment($"{ConfigPrefix}__BackendTls__RequireTlsOnIdentityHops", "true");
}
