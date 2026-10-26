// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Security.Cryptography;
using Microsoft.AspNetCore.DataProtection;

namespace Cratis.AuthProxy.OnBehalfSessions;

/// <summary>
/// Protects the on-behalf session cookie with the application's ASP.NET Core Data Protection key ring.
/// </summary>
/// <param name="dataProtectionProvider">The data-protection provider.</param>
/// <remarks>
/// The purpose string keeps every other protected cookie this proxy issues from being authentic here, and the
/// recovered record is checked for completeness as well: the payload of another protected cookie would deserialize
/// into this shape with its own fields simply missing.
/// </remarks>
public sealed class OnBehalfSessionProtector(IDataProtectionProvider dataProtectionProvider) : IOnBehalfSessionProtector
{
    /// <summary>
    /// The data-protection purpose the session is sealed under.
    /// </summary>
    public const string Purpose = "Cratis.AuthProxy.OnBehalfSession.v1";

    readonly IDataProtector _protector = dataProtectionProvider.CreateProtector(Purpose);

    /// <inheritdoc />
    public string Protect(OnBehalfSession session) => _protector.Protect(JsonSerializer.Serialize(session));

    /// <inheritdoc />
    public bool TryUnprotect(string protectedSession, out OnBehalfSession session)
    {
        session = default!;
        try
        {
            var deserialized = JsonSerializer.Deserialize<OnBehalfSession>(_protector.Unprotect(protectedSession));
            if (deserialized?.Actor is null
                || string.IsNullOrWhiteSpace(deserialized.SessionId)
                || string.IsNullOrWhiteSpace(deserialized.Actor.UserId)
                || string.IsNullOrWhiteSpace(deserialized.Tenant)
                || string.IsNullOrWhiteSpace(deserialized.Subject)
                || string.IsNullOrWhiteSpace(deserialized.Issue)
                || deserialized.ExpiresAt <= deserialized.StartedAt)
            {
                return false;
            }

            session = deserialized;
            return true;
        }
        catch (Exception exception) when (exception is CryptographicException or JsonException or FormatException)
        {
            return false;
        }
    }
}
