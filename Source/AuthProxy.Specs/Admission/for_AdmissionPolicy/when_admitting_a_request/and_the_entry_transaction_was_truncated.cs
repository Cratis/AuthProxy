// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Admission.for_AdmissionPolicy.when_admitting_a_request;

/// <summary>
/// A value cut short is refused the same way an altered one is — the caller learns nothing from the
/// difference because there is none.
/// </summary>
public class and_the_entry_transaction_was_truncated : given.an_admission_policy
{
    bool _isAdmitted;

    void Establish()
    {
        var sealedTransaction = SealedTransaction(TimeSpan.FromMinutes(10));
        Presenting($"{Cookies.EntryTransaction}={sealedTransaction[..(sealedTransaction.Length / 2)]}");
    }

    void Because() => _isAdmitted = _policy.IsAdmitted(_context, _config);

    [Fact] void should_not_admit_the_caller() => _isAdmitted.ShouldBeFalse();
}
