// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Azure.Core;
using Azure.Identity;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.DataProtection.KeyManagement;
using Microsoft.AspNetCore.DataProtection.StackExchangeRedis;
using StackExchange.Redis;
using C = Cratis.AuthProxy.Configuration;

namespace Cratis.AuthProxy.KeyRing;

/// <summary>
/// Extension methods that apply the configured Data Protection key store and key protection.
/// </summary>
public static class KeyRingExtensions
{
    /// <summary>
    /// Persists and protects the key ring the way the configuration asks.
    /// </summary>
    /// <param name="dataProtection">The <see cref="IDataProtectionBuilder"/> to configure.</param>
    /// <param name="configuration">The application configuration.</param>
    /// <returns>The same <see cref="IDataProtectionBuilder"/> for chaining.</returns>
    /// <remarks>
    /// With no <see cref="C.DataProtection"/> section this does exactly what the proxy has always done:
    /// persist to <see cref="C.AuthProxy.DataProtectionKeysPath"/> when it is set and leave the framework
    /// default otherwise.
    /// <para>
    /// A configuration the <see cref="KeyRingConfigurationValidator"/> refuses is left unapplied rather than
    /// applied halfway; the validator stops the host at startup with the reason, so nothing runs against it.
    /// </para>
    /// <para>
    /// Nothing here reaches the network while the host is being built. The blob and the vault are contacted by
    /// the first operation that needs the key ring, and the Redis connection is made then too, so an
    /// unreachable store shows up as the readiness check failing rather than as a host that never starts.
    /// </para>
    /// </remarks>
    public static IDataProtectionBuilder ApplyConfiguredKeyRing(this IDataProtectionBuilder dataProtection, IConfiguration configuration)
    {
        var settings = configuration.GetSection(C.DataProtection.SectionKey).Get<C.DataProtection>() ?? new();
        var keysPath = configuration[$"{C.AuthProxy.SectionKey}:{nameof(C.AuthProxy.DataProtectionKeysPath)}"];

        if (KeyRingConfigurationValidator.Check(settings, keysPath).Count > 0)
        {
            return dataProtection;
        }

        TokenCredential? credential = null;
        TokenCredential Credential() => credential ??= new DefaultAzureCredential(
            new DefaultAzureCredentialOptions { ManagedIdentityClientId = settings.ManagedIdentityClientId });

        switch (settings.Store)
        {
            case C.DataProtectionStore.AzureBlob:
                dataProtection.PersistKeysToAzureBlobStorage(new Uri(settings.AzureBlob!.BlobUri), Credential());
                break;

            case C.DataProtectionStore.Redis:
                PersistToRedis(dataProtection, settings.Redis!);
                break;

            default:
                if (!string.IsNullOrWhiteSpace(keysPath))
                {
                    dataProtection.PersistKeysToFileSystem(new DirectoryInfo(keysPath));
                }

                break;
        }

        if (settings.KeyVault is not null)
        {
            dataProtection.ProtectKeysWithAzureKeyVault(new Uri(settings.KeyVault.KeyIdentifier), Credential());
        }

        return dataProtection;
    }

    static void PersistToRedis(IDataProtectionBuilder dataProtection, C.RedisKeyStore redis)
    {
        // Registered with the container rather than created here, for two reasons: the connection is made on
        // the first use of the key ring instead of while the host is being built, and the container disposes
        // the multiplexer when the host stops.
        //
        // Always connected with AbortOnConnectFail off, whatever the connection string says. With it on, a
        // Redis that is down while the proxy starts makes resolving the key ring throw — and with a
        // management listener open, that is resolved while the host is starting, so the process would crash
        // instead of reporting itself not ready, and would not recover when Redis did. Off, the multiplexer
        // keeps retrying in the background, a key ring operation fails while Redis is unreachable and works
        // again once it is back, and the readiness check says which.
        dataProtection.Services.AddSingleton<IConnectionMultiplexer>(_ =>
        {
            var options = ConfigurationOptions.Parse(redis.ConnectionString);
            options.AbortOnConnectFail = false;
            return ConnectionMultiplexer.Connect(options);
        });
        dataProtection.Services
            .AddOptions<KeyManagementOptions>()
            .Configure<IConnectionMultiplexer>((options, connection) =>
                options.XmlRepository = new RedisXmlRepository(() => connection.GetDatabase(), redis.Key));
    }
}
