// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.ApplicationContract;

/// <summary>
/// Collects the standard <c language="text">Cratis:AuthProxy</c> settings a contract produces.
/// </summary>
public class ContractSettings
{
    readonly Dictionary<string, string?> _values = new(StringComparer.OrdinalIgnoreCase);

    /// <summary>
    /// Gets the number of OIDC providers written so far.
    /// </summary>
    public int OidcProviderCount { get; private set; }

    /// <summary>
    /// Gets the number of OAuth providers written so far.
    /// </summary>
    public int OAuthProviderCount { get; private set; }

    /// <summary>
    /// Gets the collected settings.
    /// </summary>
    public IReadOnlyDictionary<string, string?> Values => _values;

    /// <summary>
    /// Sets one setting under <c language="text">Cratis:AuthProxy</c>.
    /// </summary>
    /// <param name="path">The path below <c language="text">Cratis:AuthProxy</c>.</param>
    /// <param name="value">The value.</param>
    public void Set(string path, string value) => _values[$"{Configuration.AuthProxy.SectionKey}:{path}"] = value;

    /// <summary>
    /// Starts the next OIDC provider.
    /// </summary>
    /// <returns>The path of the provider below <c language="text">Cratis:AuthProxy</c>.</returns>
    public string NextOidcProvider() => $"Authentication:OidcProviders:{OidcProviderCount++}";

    /// <summary>
    /// Starts the next OAuth provider.
    /// </summary>
    /// <returns>The path of the provider below <c language="text">Cratis:AuthProxy</c>.</returns>
    public string NextOAuthProvider() => $"Authentication:OAuthProviders:{OAuthProviderCount++}";

    /// <summary>
    /// Sets list entries below a path.
    /// </summary>
    /// <param name="path">The path of the list.</param>
    /// <param name="items">The entries.</param>
    public void SetList(string path, IEnumerable<string> items)
    {
        var index = 0;
        foreach (var item in items)
        {
            Set($"{path}:{index++}", item);
        }
    }
}
