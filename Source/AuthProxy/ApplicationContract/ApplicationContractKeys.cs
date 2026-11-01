// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.ApplicationContract;

/// <summary>
/// The configuration keys of the application configuration contract.
/// </summary>
public static class ApplicationContractKeys
{
    /// <summary>
    /// The configuration section of the contract.
    /// </summary>
    public const string SectionKey = $"{Configuration.AuthProxy.SectionKey}:Application";

    /// <summary>
    /// The section holding the provider list.
    /// </summary>
    public const string ProvidersKey = $"{SectionKey}:Providers";

    /// <summary>
    /// The section holding environment values, keyed by their flat environment key.
    /// </summary>
    public const string EnvironmentKey = $"{SectionKey}:Environment";

    /// <summary>
    /// The optional name of the Cratis environment the values come from, used in messages.
    /// </summary>
    public const string EnvironmentNameKey = $"{SectionKey}:EnvironmentName";

    /// <summary>
    /// The optional directory holding one file per environment key.
    /// </summary>
    public const string SecretsDirectoryKey = $"{SectionKey}:SecretsDirectory";

    /// <summary>
    /// The flag declaring that the application has onboarding.
    /// </summary>
    public const string OnboardingKey = $"{SectionKey}:Onboarding";

    /// <summary>
    /// The flag allowing HTTP on loopback addresses.
    /// </summary>
    public const string DevelopmentKey = $"{SectionKey}:Development";

    /// <summary>
    /// The suffix of the key naming a file that holds the value of another key.
    /// </summary>
    public const string FileSuffix = "_FILE";

    /// <summary>
    /// Gets the flat environment key of a provider value.
    /// </summary>
    /// <param name="identity">The provider identity.</param>
    /// <param name="key">The provider key, for example <c language="text">clientId</c>.</param>
    /// <returns>The environment key.</returns>
    public static string ProviderValue(string identity, string key) => $"authentication.providers.{identity}.{key}";

    /// <summary>
    /// Gets the flat environment key of an onboarding value.
    /// </summary>
    /// <param name="key">The onboarding key, for example <c language="text">stageUrl</c>.</param>
    /// <returns>The environment key.</returns>
    public static string OnboardingValue(string key) => $"onboarding.{key}";
}
