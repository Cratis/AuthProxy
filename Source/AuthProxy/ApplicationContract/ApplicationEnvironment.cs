// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.ApplicationContract;

/// <summary>
/// Reads the values of a Cratis environment from the places the contract allows.
/// </summary>
/// <remarks>
/// A value is looked up in this order: the standard configuration key, a <c language="text">_FILE</c> key naming
/// a file that holds the value, and a file named after the key in the secrets directory. A value is never
/// logged and never part of a message.
/// </remarks>
/// <param name="configuration">The configuration holding the contract.</param>
public class ApplicationEnvironment(IConfiguration configuration)
{
    /// <summary>
    /// Gets the name of the Cratis environment, or a placeholder when none was given.
    /// </summary>
    public string Name => Or(configuration[ApplicationContractKeys.EnvironmentNameKey], "unnamed");

    /// <summary>
    /// Gets a value indicating whether HTTP on loopback addresses is allowed.
    /// </summary>
    public bool Development => bool.TryParse(configuration[ApplicationContractKeys.DevelopmentKey], out var value) && value;

    /// <summary>
    /// Gets a value indicating whether the application has onboarding.
    /// </summary>
    public bool Onboarding => bool.TryParse(configuration[ApplicationContractKeys.OnboardingKey], out var value) && value;

    string SecretsDirectory => configuration[ApplicationContractKeys.SecretsDirectoryKey] ?? string.Empty;

    /// <summary>
    /// Finds the value of an environment key.
    /// </summary>
    /// <param name="key">The flat environment key.</param>
    /// <returns>The value, or <see langword="null"/> when no source holds a nonempty one.</returns>
    /// <exception cref="ApplicationContractException">Thrown when a named file is missing, empty or unreadable.</exception>
    public string? Find(string key)
    {
        var direct = configuration[$"{ApplicationContractKeys.EnvironmentKey}:{key}"];
        if (!string.IsNullOrEmpty(direct))
        {
            return direct;
        }

        var filePath = configuration[$"{ApplicationContractKeys.EnvironmentKey}:{key}{ApplicationContractKeys.FileSuffix}"];
        if (!string.IsNullOrWhiteSpace(filePath))
        {
            return ReadFile(filePath, key) ?? throw new ApplicationContractException(
                $"Environment '{Name}': the file '{filePath}' named for key '{key}' does not exist or is empty.");
        }

        var directory = SecretsDirectory;
        if (!string.IsNullOrWhiteSpace(directory))
        {
            return ReadFile(Path.Combine(directory, key), key);
        }

        return null;
    }

    /// <summary>
    /// Gets the value of a key the provider cannot start without.
    /// </summary>
    /// <param name="key">The flat environment key.</param>
    /// <param name="owner">What the key belongs to, for the message, for example <c language="text">provider 'GitHub'</c>.</param>
    /// <returns>The value.</returns>
    /// <exception cref="ApplicationContractException">Thrown when no source holds the key.</exception>
    public string Require(string key, string owner) =>
        Find(key) ?? throw new ApplicationContractException(
            $"Environment '{Name}' is missing required key '{key}' for {owner}. " +
            $"Set it as the configuration key '{ApplicationContractKeys.EnvironmentKey}:{key}', " +
            $"name a file with '{ApplicationContractKeys.EnvironmentKey}:{key}{ApplicationContractKeys.FileSuffix}', " +
            $"or provide a file named '{key}' in the secrets directory.");

    static string? ReadFile(string path, string key)
    {
        if (!File.Exists(path))
        {
            return null;
        }

        try
        {
            var content = File.ReadAllText(path).TrimEnd('\r', '\n');
            return content.Length == 0 ? null : content;
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            throw new ApplicationContractException($"The file '{path}' for key '{key}' cannot be read: {exception.GetType().Name}.");
        }
    }

    static string Or(string? value, string fallback) => string.IsNullOrWhiteSpace(value) ? fallback : value;
}
