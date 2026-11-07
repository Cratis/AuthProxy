// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

namespace Cratis.AuthProxy.Security.given;

/// <summary>Two environments sharing keys, tenant membership and the same authenticated account.</summary>
public sealed class EnvironmentBindingHarness : IDisposable
{
    readonly TenantSelectionHarness _deployment = new();
    readonly string _keys = Path.Combine(Path.GetTempPath(), Path.GetRandomFileName());

    /// <summary>Initializes a new instance of the <see cref="EnvironmentBindingHarness"/> class.</summary>
    public EnvironmentBindingHarness()
    {
        Directory.CreateDirectory(_keys);
        _deployment.UserBelongsTo(TenantSelectionHarness.TenantA);
        Staging = Create("staging");
        Production = Create("production");
    }

    /// <summary>Gets the staging proxy.</summary>
    public WebApplicationFactory<Program> Staging { get; }

    /// <summary>Gets the production proxy.</summary>
    public WebApplicationFactory<Program> Production { get; }

    /// <summary>Gets the recording origin.</summary>
    public RecordingBackend Origin => _deployment.Origin;

    /// <summary>Selects the tenant in staging for the shared account.</summary>
    /// <param name="client">The staging client.</param>
    /// <returns>The selected-tenant cookie.</returns>
    public Task<string> Select(HttpClient client) => _deployment.SelectTenant(client, "alice", TenantSelectionHarness.TenantA);

    /// <summary>
    /// Changes the shared account's current memberships.
    /// </summary>
    /// <param name="tenants">The tenants the account belongs to.</param>
    public void UserBelongsTo(params string[] tenants) => _deployment.UserBelongsTo(tenants);

    /// <inheritdoc/>
    public void Dispose()
    {
        Staging.Dispose();
        Production.Dispose();
        _deployment.Dispose();
        Directory.Delete(_keys, recursive: true);
    }

    WebApplicationFactory<Program> Create(string environment) => _deployment.WithWebHostBuilder(builder => builder
        .ConfigureServices(services => services.AddDataProtection().PersistKeysToFileSystem(new(_keys)))
        .ConfigureAppConfiguration((_, config) => config.AddInMemoryCollection(new Dictionary<string, string?>
        {
            [$"{C.AuthProxy.SectionKey}:DataProtectionKeysPath"] = _keys,
            [$"{C.AuthProxy.SectionKey}:CredentialBinding:Environment"] = environment,
        })));
}
