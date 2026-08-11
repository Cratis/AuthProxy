// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.AspNetCore.DataProtection;

namespace Cratis.AuthProxy.Admission.for_AdmissionPolicy.when_admitting_a_request;

/// <summary>
/// A perfectly well-formed entry transaction sealed by another deployment — or by this one before its keys
/// were replaced — admits nobody. The seal is what makes the record evidence, and evidence issued by
/// somebody else is not evidence here.
/// </summary>
public class and_the_entry_transaction_came_from_another_key_ring : given.an_admission_policy
{
    bool _isAdmitted;

    void Establish()
    {
        var foreign = new EntryTransactionProtector(new EphemeralDataProtectionProvider());
        var transaction = new EntryTransaction(
            Transaction,
            Challenge,
            _time.GetUtcNow().AddMinutes(10));

        Presenting($"{Cookies.EntryTransaction}={foreign.Protect(transaction)}");
    }

    void Because() => _isAdmitted = _policy.IsAdmitted(_context, _config);

    [Fact] void should_not_admit_the_caller() => _isAdmitted.ShouldBeFalse();
}
