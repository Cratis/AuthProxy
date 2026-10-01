// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.KeyRing;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

namespace Cratis.AuthProxy.Management.for_DataProtectionReadiness;

/// <summary>
/// The readiness round-trip does not care where the key ring lives, which is what lets it cover a shared store
/// without knowing about one. A replica that cannot reach the Redis holding the key ring cannot read a single
/// session, yet accepts sockets — so it must report itself not ready instead of being sent traffic.
/// </summary>
public class when_the_shared_store_is_unreachable : Specification
{
    ServiceProvider _services;
    bool _ready;

    void Establish()
    {
        var configuration = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?>
        {
            [$"{C.DataProtection.SectionKey}:Store"] = "Redis",
            [$"{C.DataProtection.SectionKey}:Redis:ConnectionString"] = "127.0.0.1:1,connectTimeout=300,syncTimeout=300",
        }).Build();

        var services = new ServiceCollection();
        services.AddLogging();
        services.AddDataProtection().ApplyConfiguredKeyRing(configuration);
        _services = services.BuildServiceProvider();
    }

    async Task Because() => _ready = await new DataProtectionReadiness(
        _services.GetRequiredService<IDataProtectionProvider>(),
        _services.GetRequiredService<ILogger<DataProtectionReadiness>>()).IsReady(CancellationToken.None);

    [Fact] void should_not_be_ready() => _ready.ShouldBeFalse();

    void Destroy() => _services.Dispose();
}
