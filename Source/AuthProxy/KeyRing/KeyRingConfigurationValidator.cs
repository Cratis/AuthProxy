// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.Extensions.Options;
using C = Cratis.AuthProxy.Configuration;

namespace Cratis.AuthProxy.KeyRing;

/// <summary>
/// Refuses a Data Protection configuration that names a store it cannot use, or says two things at once.
/// </summary>
/// <remarks>
/// A key ring that is not what the operator meant is the quietest failure this component has. The proxy
/// starts, people sign in, and each replica encrypts with a key ring of its own — so a session works until a
/// request lands on another replica, which is exactly the intermittent, load-dependent symptom that is
/// hardest to trace back to a setting. Every contradiction is therefore named at startup, at the key, rather
/// than resolved by picking a winner.
/// </remarks>
public class KeyRingConfigurationValidator : IValidateOptions<C.AuthProxy>
{
    /// <inheritdoc/>
    public ValidateOptionsResult Validate(string? name, C.AuthProxy options) =>
        Check(options.DataProtection, options.DataProtectionKeysPath) is { Count: > 0 } failures
            ? ValidateOptionsResult.Fail(failures)
            : ValidateOptionsResult.Success;

    /// <summary>
    /// Finds everything wrong with a Data Protection configuration.
    /// </summary>
    /// <param name="settings">The Data Protection section.</param>
    /// <param name="keysPath">The configured file system key path, if any.</param>
    /// <returns>One message per problem; empty when the configuration is usable.</returns>
    internal static List<string> Check(C.DataProtection settings, string? keysPath)
    {
        var failures = new List<string>();
        var store = $"{C.DataProtection.SectionKey}:{nameof(C.DataProtection.Store)}";

        if (settings.Store != C.DataProtectionStore.FileSystem && !string.IsNullOrWhiteSpace(keysPath))
        {
            failures.Add($"{C.AuthProxy.SectionKey}:{nameof(C.AuthProxy.DataProtectionKeysPath)} is set, but {store} is '{settings.Store}', so the key ring would not be stored there. Remove the path, or set {store} to '{nameof(C.DataProtectionStore.FileSystem)}'.");
        }

        if (settings.Store == C.DataProtectionStore.AzureBlob)
        {
            CheckAzureBlob(settings, failures);
        }
        else if (settings.AzureBlob is not null)
        {
            failures.Add($"{C.DataProtection.SectionKey}:{nameof(C.DataProtection.AzureBlob)} is set, but {store} is '{settings.Store}', so it would be ignored. Set {store} to '{nameof(C.DataProtectionStore.AzureBlob)}', or remove the section.");
        }

        if (settings.Store == C.DataProtectionStore.Redis)
        {
            CheckRedis(settings, failures);
        }
        else if (settings.Redis is not null)
        {
            failures.Add($"{C.DataProtection.SectionKey}:{nameof(C.DataProtection.Redis)} is set, but {store} is '{settings.Store}', so it would be ignored. Set {store} to '{nameof(C.DataProtectionStore.Redis)}', or remove the section.");
        }

        if (settings.KeyVault is not null && !IsHttps(settings.KeyVault.KeyIdentifier))
        {
            failures.Add($"{C.DataProtection.SectionKey}:{nameof(C.DataProtection.KeyVault)}:{nameof(C.KeyVaultKeyProtection.KeyIdentifier)} is '{settings.KeyVault.KeyIdentifier}', which is not an absolute https URI. Write it as 'https://<vault>.vault.azure.net/keys/<key-name>'.");
        }

        return failures;
    }

    static void CheckAzureBlob(C.DataProtection settings, List<string> failures)
    {
        var key = $"{C.DataProtection.SectionKey}:{nameof(C.DataProtection.AzureBlob)}:{nameof(C.AzureBlobKeyStore.BlobUri)}";
        var uri = settings.AzureBlob?.BlobUri;

        if (string.IsNullOrWhiteSpace(uri))
        {
            failures.Add($"{C.DataProtection.SectionKey}:{nameof(C.DataProtection.Store)} is '{nameof(C.DataProtectionStore.AzureBlob)}', but {key} is not set. Write it as 'https://<account>.blob.core.windows.net/<container>/<blob>'.");
        }
        else if (!IsHttps(uri))
        {
            failures.Add($"{key} is '{uri}', which is not an absolute https URI. Write it as 'https://<account>.blob.core.windows.net/<container>/<blob>'.");
        }
    }

    static void CheckRedis(C.DataProtection settings, List<string> failures)
    {
        var connectionString = $"{C.DataProtection.SectionKey}:{nameof(C.DataProtection.Redis)}:{nameof(C.RedisKeyStore.ConnectionString)}";

        if (string.IsNullOrWhiteSpace(settings.Redis?.ConnectionString))
        {
            failures.Add($"{C.DataProtection.SectionKey}:{nameof(C.DataProtection.Store)} is '{nameof(C.DataProtectionStore.Redis)}', but {connectionString} is not set.");
        }

        if (settings.Redis is not null && string.IsNullOrWhiteSpace(settings.Redis.Key))
        {
            failures.Add($"{C.DataProtection.SectionKey}:{nameof(C.DataProtection.Redis)}:{nameof(C.RedisKeyStore.Key)} is blank. Leave it unset for '{C.RedisKeyStore.DefaultKey}', or name the Redis key.");
        }
    }

    static bool IsHttps(string? value) =>
        Uri.TryCreate(value, UriKind.Absolute, out var uri) && uri.Scheme == Uri.UriSchemeHttps;
}
