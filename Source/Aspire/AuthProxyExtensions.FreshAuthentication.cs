// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Aspire;

public static partial class AuthProxyExtensions
{
    /// <summary>Requires a recent interactive authentication on a protected service path.</summary>
    /// <typeparam name="T">The resource type.</typeparam>
    /// <param name="builder">The resource builder.</param>
    /// <param name="serviceName">The configured service key.</param>
    /// <param name="path">The service-local path; root covers the whole service.</param>
    /// <param name="maxAge">The maximum authentication age (one second through one day); defaults to five minutes.</param>
    /// <param name="prefix">Whether descendants of the path also match.</param>
    /// <param name="methods">The HTTP methods to match; empty matches all methods.</param>
    /// <returns>The same builder for chaining. Repeated calls append rules.</returns>
    public static IResourceBuilder<T> WithFreshAuthentication<T>(
        this IResourceBuilder<T> builder,
        string serviceName,
        string path,
        TimeSpan? maxAge = null,
        bool prefix = false,
        params string[] methods)
        where T : IResourceWithEnvironment
    {
        var age = maxAge ?? TimeSpan.FromMinutes(5);
        ArgumentOutOfRangeException.ThrowIfLessThan(age, TimeSpan.FromSeconds(1), nameof(maxAge));
        ArgumentOutOfRangeException.ThrowIfGreaterThan(age, TimeSpan.FromDays(1), nameof(maxAge));
        var annotation = GetOrCreateAnnotation(builder.Resource);
        annotation.FreshAuthenticationCounts.TryGetValue(serviceName, out var index);
        var key = $"{ConfigPrefix}__Services__{serviceName}__FreshAuthentication__{index}";
        builder.WithEnvironment($"{key}__Path", path);
        builder.WithEnvironment($"{key}__Prefix", prefix.ToString());
        builder.WithEnvironment($"{key}__MaxAge", age.ToString("c", CultureInfo.InvariantCulture));
        for (var method = 0; method < methods.Length; method++)
        {
            builder.WithEnvironment($"{key}__Methods__{method}", methods[method]);
        }
        annotation.FreshAuthenticationCounts[serviceName] = index + 1;
        return builder;
    }
}
