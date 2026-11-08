// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Aspire;

public static partial class AuthProxyExtensions
{
    static void ApplyLocalTrustedProxyDefault(IResourceBuilder<AuthProxyResource> builder)
    {
        if (!builder.ApplicationBuilder.ExecutionContext.IsRunMode)
        {
            return;
        }

        // Append after the caller's environment callbacks so explicit settings always win.
        builder.ApplicationBuilder.Eventing.Subscribe<BeforeStartEvent>((_, _) =>
        {
            builder.WithEnvironment(context =>
            {
                const string modeKey = "Cratis__AuthProxy__Ingress__Mode";
                const string proxiesKey = "Cratis__AuthProxy__Ingress__TrustedProxies";
                var hasExplicitBoundary = context.EnvironmentVariables.Keys.Any(key =>
                    string.Equals(key, modeKey, StringComparison.OrdinalIgnoreCase)
                    || string.Equals(key, proxiesKey, StringComparison.OrdinalIgnoreCase)
                    || key.StartsWith(proxiesKey + "__", StringComparison.OrdinalIgnoreCase));
                if (!hasExplicitBoundary)
                {
                    context.EnvironmentVariables[modeKey] = "TrustAny";
                }
            });
            return Task.CompletedTask;
        });
    }
}
