// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Admission.for_AdmissionPolicy.when_admitting_a_request;

/// <summary>
/// A browser holding an authentic, unexpired entry transaction is admitted, and the request proceeds
/// exactly as it would in a deployment that never closed the door.
/// </summary>
public class and_a_live_entry_transaction_is_presented : given.an_admission_policy
{
    bool _isAdmitted;

    void Establish() => Presenting($"{Cookies.EntryTransaction}={SealedTransaction(TimeSpan.FromMinutes(10))}");

    void Because() => _isAdmitted = _policy.IsAdmitted(_context, _config);

    [Fact] void should_admit_the_caller() => _isAdmitted.ShouldBeTrue();
}
