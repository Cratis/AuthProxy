// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Security.Cryptography;
using Microsoft.AspNetCore.DataProtection;

namespace Cratis.AuthProxy.Invites;

/// <summary>
/// Protects invitation-entry state with the application's ASP.NET Core Data Protection key ring.
/// </summary>
/// <param name="dataProtectionProvider">The data-protection provider.</param>
public sealed class InvitationEntryStateProtector(IDataProtectionProvider dataProtectionProvider) : IInvitationEntryStateProtector
{
    const string Purpose = "Cratis.AuthProxy.InvitationEntryState.v1";
    readonly IDataProtector _protector = dataProtectionProvider.CreateProtector(Purpose);

    /// <inheritdoc />
    public string Protect(InvitationEntryState state) => _protector.Protect(JsonSerializer.Serialize(state));

    /// <inheritdoc />
    public bool TryUnprotect(string protectedState, out InvitationEntryState state)
    {
        state = default!;
        try
        {
            var json = _protector.Unprotect(protectedState);
            var deserialized = JsonSerializer.Deserialize<InvitationEntryState>(json);
            if (deserialized is null)
            {
                return false;
            }

            state = deserialized;
            return true;
        }
        catch (Exception exception) when (exception is CryptographicException or JsonException)
        {
            return false;
        }
    }
}
