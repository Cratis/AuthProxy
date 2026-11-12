// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using StackExchange.Redis;
using Testcontainers.Redis;

namespace Cratis.AuthProxy.Integration.Specs;

/// <summary>Owns a disposable Redis process with persistence disabled.</summary>
public sealed class RedisReplayFixture : IAsyncLifetime
{
    readonly RedisContainer _container = new RedisBuilder("redis:7.4.2-alpine")
        .WithCommand("redis-server", "--save", string.Empty, "--appendonly", "no", "--maxmemory-policy", "noeviction")
        .Build();
    ConnectionMultiplexer _connection = null!;

    /// <summary>Gets the endpoint for independent production-store connections.</summary>
    public string Endpoint => _container.GetConnectionString();

    /// <summary>Gets the database used to inspect replay evidence.</summary>
    public IDatabase Database => _connection.GetDatabase();

    /// <inheritdoc/>
    public async ValueTask InitializeAsync()
    {
        await _container.StartAsync();
        _connection = await ConnectionMultiplexer.ConnectAsync(Endpoint);
    }

    /// <summary>Restarts Redis without preserving in-memory replay evidence.</summary>
    /// <returns>The restart operation.</returns>
    public async Task Restart()
    {
        await _container.StopAsync();
        await _container.StartAsync();
        await _connection.DisposeAsync();
        _connection = await ConnectionMultiplexer.ConnectAsync(Endpoint);
    }

    /// <inheritdoc/>
    public async ValueTask DisposeAsync()
    {
        await _connection.DisposeAsync();
        await _container.DisposeAsync();
    }
}
