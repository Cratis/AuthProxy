// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.DataProtection.KeyManagement;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

namespace Cratis.AuthProxy.KeyRing.given;

/// <summary>
/// A Data Protection stack configured from keys the way a deployment writes them, exposing what the
/// framework ended up persisting to and protecting with.
/// </summary>
/// <remarks>
/// Built from configuration keys rather than from an options object, because the keys are the surface an
/// operator actually sets, and binding them is the part that can silently be wrong. Resolving
/// <see cref="KeyManagementOptions"/> is enough to see the chosen store without reaching it.
/// </remarks>
public class a_key_ring_configuration : Specification
{
    protected const string Section = "Cratis:AuthProxy";

    protected ServiceProvider _services;
    protected KeyManagementOptions _options;

    protected virtual IDictionary<string, string?> Settings => new Dictionary<string, string?>();

    protected void Build()
    {
        var configuration = new ConfigurationBuilder().AddInMemoryCollection(Settings).Build();

        var services = new ServiceCollection();
        services.AddLogging();
        services.AddDataProtection()
            .SetApplicationName("Cratis.AuthProxy.Specs")
            .ApplyConfiguredKeyRing(configuration);

        _services = services.BuildServiceProvider();
        _options = _services.GetRequiredService<Microsoft.Extensions.Options.IOptions<KeyManagementOptions>>().Value;
    }

    void Destroy() => _services?.Dispose();
}
