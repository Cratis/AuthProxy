// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.OnBehalfSessions.given;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

namespace Cratis.AuthProxy.Scenarios.when_client_credentials_token_is_requested;

/// <summary>
/// Web application factory whose clock only moves when a spec moves it.
/// </summary>
public class ClockedAuthProxyFactory : AuthProxyFactory
{
    /// <summary>
    /// Gets the clock, anchored at the real current time because data protection still checks the wall clock for access tokens.
    /// </summary>
    public ManualTime Time { get; } = new(DateTimeOffset.UtcNow);

    /// <summary>
    /// Gets the configured family lifetime, or <see langword="null"/> to use the default.
    /// </summary>
    protected virtual string? FamilyLifetime => null;

    /// <inheritdoc/>
    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        base.ConfigureWebHost(builder);

        if (FamilyLifetime is not null)
        {
            builder.ConfigureAppConfiguration((_, config) =>
                config.AddInMemoryCollection(new Dictionary<string, string?>
                {
                    [$"{C.AuthProxy.SectionKey}:Services:portal:ClientCredentials:RefreshTokenFamilyLifetime"] = FamilyLifetime,
                }));
        }

        builder.ConfigureTestServices(services => services.AddSingleton<TimeProvider>(Time));
    }
}
