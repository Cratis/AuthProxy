// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.Configuration;

namespace Cratis.AuthProxy.ApplicationContract;

/// <summary>
/// The translations of every provider kind the contract supports.
/// </summary>
public static class ProviderTranslations
{
    static readonly IProviderTranslation[] _all =
    [
        new OidcProviderTranslation(
            ProviderKind.EntraId,
            OidcProviderType.Microsoft,
            "oid",
            ["tenantId", "clientId", "clientSecret"],
            values => values.Find("authority") is { } authority
                ? values.AddressOr("authority", authority)
                : $"https://login.microsoftonline.com/{TenantId(values)}/v2.0"),
        new GitHubProviderTranslation(),
        new OidcProviderTranslation(ProviderKind.Google, OidcProviderType.Google, "sub", ["clientId", "clientSecret"], values => values.AddressOr("authority", "https://accounts.google.com")),
        new OidcProviderTranslation(ProviderKind.Apple, OidcProviderType.Apple, "sub", ["clientId", "clientSecret"], values => values.AddressOr("authority", "https://appleid.apple.com")),
        new OidcProviderTranslation(ProviderKind.OpenId, OidcProviderType.Custom, "sub", ["authority", "clientId", "clientSecret"], values => values.RequireAddress("authority"))
    ];

    /// <summary>
    /// Gets every translation.
    /// </summary>
    public static IReadOnlyList<IProviderTranslation> All => _all;

    /// <summary>
    /// Finds the translation for a kind name.
    /// </summary>
    /// <param name="kind">The kind name, case-insensitive.</param>
    /// <returns>The translation, or <see langword="null"/> when the kind is unknown.</returns>
    public static IProviderTranslation? Find(string kind) =>
        Enum.TryParse<ProviderKind>(kind, ignoreCase: true, out var parsed)
            ? _all.FirstOrDefault(_ => _.Kind == parsed)
            : null;

    static string TenantId(ProviderValues values)
    {
        var tenant = values.Require("tenantId");
        if (tenant.Any(_ => !(char.IsAsciiLetterOrDigit(_) || _ is '-' or '.')))
        {
            throw new ApplicationContractException(
                $"Environment '{values.Environment.Name}': key '{ApplicationContractKeys.ProviderValue(values.Identity, "tenantId")}' must be a tenant id or domain.");
        }

        return tenant;
    }
}
