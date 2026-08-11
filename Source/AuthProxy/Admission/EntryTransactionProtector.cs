// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Security.Cryptography;
using Microsoft.AspNetCore.DataProtection;

namespace Cratis.AuthProxy.Admission;

/// <summary>
/// Protects the entry transaction with the application's ASP.NET Core Data Protection key ring.
/// </summary>
/// <param name="dataProtectionProvider">The data-protection provider.</param>
/// <remarks>
/// The purpose string is its own, so a value from any other protected cookie this proxy issues is simply
/// not authentic here — the key ring is shared, the purposes are not.
/// <para>
/// The purpose is the only thing separating this cookie from the neighboring invitation-entry one, and a
/// purpose is a string somebody can change without noticing what it was holding apart. So the recovered
/// record is checked as well: the payload of any other protected cookie deserializes into this shape with
/// its own fields simply missing, and a record whose transaction or challenge is absent is not one this
/// proxy ever wrote.
/// </para>
/// </remarks>
public sealed class EntryTransactionProtector(IDataProtectionProvider dataProtectionProvider) : IEntryTransactionProtector
{
    /// <summary>
    /// The data-protection purpose the entry transaction is sealed under.
    /// </summary>
    /// <remarks>
    /// Public so a spec can pin the exact literal. Two protected cookies sharing one key ring are kept apart
    /// by nothing but this string, and a rename that made it collide with another purpose would leave both
    /// values mutually authentic with no error anywhere.
    /// </remarks>
    public const string Purpose = "Cratis.AuthProxy.EntryTransaction.v1";

    readonly IDataProtector _protector = dataProtectionProvider.CreateProtector(Purpose);

    /// <inheritdoc />
    public string Protect(EntryTransaction transaction) => _protector.Protect(JsonSerializer.Serialize(transaction));

    /// <inheritdoc />
    public bool TryUnprotect(string protectedTransaction, out EntryTransaction transaction)
    {
        transaction = default!;
        try
        {
            var json = _protector.Unprotect(protectedTransaction);
            var deserialized = JsonSerializer.Deserialize<EntryTransaction>(json);

            // The nullable annotations on the record are compile-time only: System.Text.Json fills a missing
            // property with null without complaint, so a payload that is not an entry transaction arrives
            // here as one whose values are simply absent — and absent values are what the admission check
            // would otherwise never look at.
            if (deserialized is null
                || string.IsNullOrEmpty(deserialized.Transaction)
                || string.IsNullOrEmpty(deserialized.Challenge))
            {
                return false;
            }

            transaction = deserialized;
            return true;
        }
        catch (Exception exception) when (exception is CryptographicException or JsonException or FormatException)
        {
            return false;
        }
    }
}
