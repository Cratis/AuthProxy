// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Security.Cryptography;
using System.Text;
using Microsoft.IdentityModel.Tokens;

namespace Cratis.AuthProxy.Code;

/// <summary>
/// Creates and checks the salted hash a code is stored as.
/// </summary>
static class CodeHash
{
    /// <summary>
    /// Creates a random salt.
    /// </summary>
    /// <returns>The salt.</returns>
    internal static string NewSalt() => Base64UrlEncoder.Encode(RandomNumberGenerator.GetBytes(16));

    /// <summary>
    /// Creates a random decimal code.
    /// </summary>
    /// <param name="length">The number of digits.</param>
    /// <returns>The code, zero-padded to the length.</returns>
    internal static string NewCode(int length)
    {
        var digits = new char[length];
        for (var index = 0; index < length; index++)
        {
            digits[index] = (char)('0' + RandomNumberGenerator.GetInt32(10));
        }

        return new string(digits);
    }

    /// <summary>
    /// Hashes a code with a salt.
    /// </summary>
    /// <param name="salt">The salt.</param>
    /// <param name="code">The code.</param>
    /// <returns>The hash.</returns>
    internal static string Compute(string salt, string code) =>
        Base64UrlEncoder.Encode(HMACSHA256.HashData(Encoding.UTF8.GetBytes(salt), Encoding.UTF8.GetBytes(code)));

    /// <summary>
    /// Checks a presented code against a stored hash without leaking where they differ.
    /// </summary>
    /// <param name="salt">The salt.</param>
    /// <param name="hash">The stored hash.</param>
    /// <param name="code">The presented code.</param>
    /// <returns><see langword="true"/> when the code matches.</returns>
    internal static bool Matches(string salt, string hash, string code) =>
        CryptographicOperations.FixedTimeEquals(Encoding.ASCII.GetBytes(Compute(salt, code)), Encoding.ASCII.GetBytes(hash));
}
