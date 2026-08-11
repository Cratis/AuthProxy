// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Text.Json;
using Cratis.AuthProxy.Invites;
using Microsoft.AspNetCore.DataProtection;

namespace Cratis.AuthProxy.Admission.for_EntryTransactionProtector;

/// <summary>
/// A record that is not an entry transaction is refused even when it arrives correctly sealed — because the
/// seal proves who wrote it, and nothing about what it is.
/// </summary>
/// <remarks>
/// The invitation entry state is the neighbor that matters: it is protected with the same key ring, it
/// carries its own transaction and challenge under different property names, and it carries an
/// <c>ExpiresAt</c> that is live for exactly the same reason this one's is. Deserialized as an entry
/// transaction it yields a record whose transaction and challenge are null and whose expiry is in the
/// future — and the admission check looks at the expiry and nothing else, so it admits.
/// <para>
/// Today only the purpose string stands between the two, and a purpose is a literal somebody can change
/// without knowing what it was holding apart. Refusing a record whose own values are missing is the half of
/// that which does not depend on remembering.
/// </para>
/// </remarks>
public class when_a_foreign_record_was_sealed_under_this_purpose : Specification
{
    EntryTransactionProtector _protector;
    string _sealed;
    bool _recovered;

    void Establish()
    {
        var provider = new EphemeralDataProtectionProvider();
        _protector = new EntryTransactionProtector(provider);

        var foreign = new InvitationEntryState(
            "33333333-3333-3333-3333-333333333333",
            "an-invitation",
            "3f9c0a1b7e2d4c6f",
            "8b1d5e7a0c3f2941",
            "a-capability-hash",
            DateTimeOffset.UtcNow.AddMinutes(10));

        _sealed = provider.CreateProtector(EntryTransactionProtector.Purpose).Protect(JsonSerializer.Serialize(foreign));
    }

    void Because() => _recovered = _protector.TryUnprotect(_sealed, out _);

    [Fact] void should_not_recover_it() => _recovered.ShouldBeFalse();
}
