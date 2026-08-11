// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Admission.for_AdmissionPolicy.when_admitting_a_request;

/// <summary>
/// A value the browser changed is not the value AuthProxy sealed, and is treated as no value at all.
/// </summary>
public class and_the_entry_transaction_was_altered : given.an_admission_policy
{
    bool _isAdmitted;

    void Establish()
    {
        var sealedTransaction = SealedTransaction(TimeSpan.FromMinutes(10));
        var altered = string.Concat(sealedTransaction.AsSpan(0, sealedTransaction.Length - 1), sealedTransaction[^1] == 'A' ? "B" : "A");
        Presenting($"{Cookies.EntryTransaction}={altered}");
    }

    void Because() => _isAdmitted = _policy.IsAdmitted(_context, _config);

    [Fact] void should_not_admit_the_caller() => _isAdmitted.ShouldBeFalse();
}
