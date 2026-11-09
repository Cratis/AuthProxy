// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Security.Cryptography;
using System.Text;

namespace Cratis.AuthProxy.BearerRoutes.PersonalAccessTokens;

/// <summary>
/// Builds well-formed personal access token values for specs, following the published wire format.
/// </summary>
public static class TestPersonalAccessTokens
{
    /// <summary>
    /// Creates a token with a matching checksum.
    /// </summary>
    /// <param name="resourceKey">The resource key prefix.</param>
    /// <param name="seed">A character repeated as the secret.</param>
    /// <returns>The token.</returns>
    public static string Create(string resourceKey, char seed = 'a')
    {
        var body = $"{resourceKey}_pat_v1_{new string(seed, 64)}";
        return $"{body}_{Checksum(body)}";
    }

    /// <summary>
    /// Creates a token whose checksum is wrong.
    /// </summary>
    /// <param name="resourceKey">The resource key prefix.</param>
    /// <returns>The token.</returns>
    public static string CreateWithBadChecksum(string resourceKey)
    {
        var body = $"{resourceKey}_pat_v1_{new string('a', 64)}";
        var checksum = Checksum(body);
        return $"{body}_{(checksum[0] == '0' ? '1' : '0')}{checksum[1..]}";
    }

    static string Checksum(string body) =>
        Convert.ToHexStringLower(SHA256.HashData(Encoding.ASCII.GetBytes(body))[..4]);
}
