// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Text.RegularExpressions;

namespace Cratis.AuthProxy.ApplicationContract;

/// <summary>
/// Turns the application configuration contract into the standard <c language="text">Cratis:AuthProxy</c> settings.
/// </summary>
public static partial class ApplicationContractTranslator
{
    [GeneratedRegex(@"^[A-Za-z0-9][A-Za-z0-9 _-]*$", RegexOptions.None, matchTimeoutMilliseconds: 1000)]
    private static partial Regex IdentityPattern { get; }

    /// <summary>
    /// Translates the contract. Returns no settings when the contract declares no providers and no onboarding.
    /// </summary>
    /// <param name="configuration">The configuration holding the contract.</param>
    /// <returns>The settings to add on top of the configuration.</returns>
    /// <exception cref="ApplicationContractException">Thrown when the contract is incomplete or invalid.</exception>
    public static IReadOnlyDictionary<string, string?> Translate(IConfiguration configuration)
    {
        var providers = configuration.GetSection(ApplicationContractKeys.ProvidersKey).Get<List<ApplicationProvider>>() ?? [];
        var environment = new ApplicationEnvironment(configuration);
        var settings = new ContractSettings();

        if (providers.Count > 0)
        {
            RejectExplicitProviders(configuration, environment);
            var identities = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (var provider in providers)
            {
                var translation = Resolve(provider, environment);
                if (!identities.Add(provider.Identity))
                {
                    throw new ApplicationContractException(
                        $"Environment '{environment.Name}': provider identity '{provider.Identity}' is used twice. Give each provider of the same kind its own alias.");
                }

                translation.Translate(new ProviderValues(provider.Identity, translation.Kind, environment), settings);
            }
        }

        if (environment.Onboarding)
        {
            OnboardingTranslation.Translate(environment, settings);
        }

        return settings.Values;
    }

    static IProviderTranslation Resolve(ApplicationProvider provider, ApplicationEnvironment environment)
    {
        var translation = ProviderTranslations.Find(provider.Kind)
            ?? throw new ApplicationContractException(
                $"Environment '{environment.Name}': provider kind '{provider.Kind}' is unknown. Use one of {string.Join(", ", ProviderTranslations.All.Select(_ => _.Kind))}.");

        if (!IdentityPattern.IsMatch(provider.Identity))
        {
            throw new ApplicationContractException(
                $"Environment '{environment.Name}': the identity '{provider.Identity}' of a {provider.Kind} provider must start with a letter or digit and use only letters, digits, spaces, hyphens and underscores.");
        }

        return translation;
    }

    static void RejectExplicitProviders(IConfiguration configuration, ApplicationEnvironment environment)
    {
        const string authentication = Configuration.Authentication.SectionKey;
        if (configuration.GetSection($"{authentication}:OidcProviders").GetChildren().Any()
            || configuration.GetSection($"{authentication}:OAuthProviders").GetChildren().Any())
        {
            throw new ApplicationContractException(
                $"Environment '{environment.Name}': '{ApplicationContractKeys.ProvidersKey}' cannot be combined with providers configured under '{authentication}'. Use one or the other.");
        }
    }
}
