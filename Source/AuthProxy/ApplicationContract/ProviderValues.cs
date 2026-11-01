// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.ApplicationContract;

/// <summary>
/// Reads the values of one provider from the environment, naming the provider in every failure.
/// </summary>
/// <param name="identity">The provider identity.</param>
/// <param name="kind">The provider kind.</param>
/// <param name="environment">The environment the values come from.</param>
public class ProviderValues(string identity, ProviderKind kind, ApplicationEnvironment environment)
{
    /// <summary>
    /// Gets the provider identity.
    /// </summary>
    public string Identity => identity;

    /// <summary>
    /// Gets the environment.
    /// </summary>
    public ApplicationEnvironment Environment => environment;

    /// <summary>
    /// Gets a required value.
    /// </summary>
    /// <param name="key">The provider key.</param>
    /// <returns>The value.</returns>
    public string Require(string key) =>
        environment.Require(ApplicationContractKeys.ProviderValue(identity, key), $"provider '{identity}' (kind {kind})");

    /// <summary>
    /// Gets an optional value.
    /// </summary>
    /// <param name="key">The provider key.</param>
    /// <returns>The value, or <see langword="null"/>.</returns>
    public string? Find(string key) => environment.Find(ApplicationContractKeys.ProviderValue(identity, key));

    /// <summary>
    /// Gets a required URL value.
    /// </summary>
    /// <param name="key">The provider key.</param>
    /// <returns>The validated URL.</returns>
    public string RequireAddress(string key) => ContractUrl.Validate(Require(key), ApplicationContractKeys.ProviderValue(identity, key), environment);

    /// <summary>
    /// Gets an optional URL value, or a default.
    /// </summary>
    /// <param name="key">The provider key.</param>
    /// <param name="fallback">The URL used when the environment has none.</param>
    /// <returns>The validated URL.</returns>
    public string AddressOr(string key, string fallback) =>
        ContractUrl.Validate(Find(key) ?? fallback, ApplicationContractKeys.ProviderValue(identity, key), environment);

    /// <summary>
    /// Gets the scopes, split on commas and whitespace, or the defaults.
    /// </summary>
    /// <param name="defaults">The scopes used when the environment has none.</param>
    /// <returns>The scopes.</returns>
    public string[] Scopes(params string[] defaults) =>
        Find("scopes")?.Split([',', ' ', '\t', '\n'], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries) ?? defaults;

    /// <summary>
    /// Gets the lowercase key AuthProxy knows the provider by for invitations.
    /// </summary>
    /// <returns>The provider key.</returns>
    public string ProviderKey() => identity.ToLowerInvariant().Replace(' ', '-');

    /// <summary>
    /// Gets whether the provider completes invitations: the explicit <c language="text">invitationCompletion</c> value,
    /// otherwise whether the application has onboarding.
    /// </summary>
    /// <returns><see langword="true"/> when invitation completion is enabled.</returns>
    public bool InvitationCompletion() =>
        bool.TryParse(Find("invitationCompletion"), out var explicitValue) ? explicitValue && environment.Onboarding : environment.Onboarding;
}
