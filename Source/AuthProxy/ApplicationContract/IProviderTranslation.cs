// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.ApplicationContract;

/// <summary>
/// Defines how one provider kind is mapped onto AuthProxy's identity-provider options.
/// </summary>
public interface IProviderTranslation
{
    /// <summary>
    /// Gets the kind the translation handles.
    /// </summary>
    ProviderKind Kind { get; }

    /// <summary>
    /// Gets the environment keys, relative to the provider, that must be present.
    /// </summary>
    IReadOnlyList<string> RequiredKeys { get; }

    /// <summary>
    /// Gets the environment keys, relative to the provider, that may be present.
    /// </summary>
    IReadOnlyList<string> OptionalKeys { get; }

    /// <summary>
    /// Writes the provider's options.
    /// </summary>
    /// <param name="values">The provider's values.</param>
    /// <param name="settings">The settings to write into.</param>
    void Translate(ProviderValues values, ContractSettings settings);
}
