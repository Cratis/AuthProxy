// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Admission.for_AdmissionPolicy.when_admitting_a_request;

/// <summary>
/// An entry expires on AuthProxy's own clock rather than on the browser's willingness to stop sending the
/// cookie. A cookie whose <c>Max-Age</c> has passed is simply one a browser has been asked not to send —
/// nothing stops one being sent anyway.
/// </summary>
public class and_the_entry_transaction_has_expired : given.an_admission_policy
{
    bool _isAdmitted;

    void Establish()
    {
        Presenting($"{Cookies.EntryTransaction}={SealedTransaction(TimeSpan.FromMinutes(10))}");
        _time.Now = _time.Now.AddMinutes(11);
    }

    void Because() => _isAdmitted = _policy.IsAdmitted(_context, _config);

    [Fact] void should_not_admit_the_caller() => _isAdmitted.ShouldBeFalse();
}
