// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Text.Json;
using Microsoft.AspNetCore.DataProtection;

namespace Cratis.AuthProxy.Admission.for_EntryTransactionProtector.when_a_partial_record_was_sealed_under_this_purpose;

/// <summary>
/// A sealed record that names a transaction but no challenge is refused, so the challenge half of the
/// emptiness guard is answerable on its own.
/// </summary>
/// <remarks>
/// The neighboring invitation entry state carries neither name, so the one spec that seals it is refused by
/// whichever of the two checks happens to survive — deleting either alone leaves that spec green. A payload
/// carrying exactly one of the pair is the only shape that makes each check the sole reason for the refusal,
/// and a check nothing can be shown to depend on is a check the next reader is free to remove.
/// </remarks>
public class and_only_the_transaction_is_present : Specification
{
    EntryTransactionProtector _protector;
    string _sealed;
    bool _recovered;

    void Establish()
    {
        var provider = new EphemeralDataProtectionProvider();
        _protector = new EntryTransactionProtector(provider);

        // Sealed from a shape rather than from the record, because the record cannot express a value this
        // proxy never wrote — and a value this proxy never wrote is the whole of what the guard is for.
        var partial = new
        {
            Transaction = "3f9c0a1b7e2d4c6f",
            ExpiresAt = DateTimeOffset.UtcNow.AddMinutes(10),
        };

        _sealed = provider.CreateProtector(EntryTransactionProtector.Purpose).Protect(JsonSerializer.Serialize(partial));
    }

    void Because() => _recovered = _protector.TryUnprotect(_sealed, out _);

    [Fact] void should_not_recover_it() => _recovered.ShouldBeFalse();
}
