// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Admission.for_AdmissionPolicy.when_admitting_a_request;

/// <summary>
/// A request carrying no entry transaction is not admitted.
/// <para>
/// This is the one spec the whole feature hangs on. The neighboring invitation binding
/// (<c>InvitationAuthenticationState.TryBindPendingInvitation</c>) deliberately answers the opposite — it
/// returns <see langword="true"/> when its cookie is absent, because it validates a transaction that
/// exists rather than requiring one. Borrowing that shape here would leave a gate that admits everybody
/// while every happy-path spec above still passes and every refusal spec still refuses, because they all
/// present something.
/// </para>
/// </summary>
public class and_nothing_is_presented : given.an_admission_policy
{
    bool _isAdmitted;

    void Because() => _isAdmitted = _policy.IsAdmitted(_context, _config);

    [Fact] void should_not_admit_the_caller() => _isAdmitted.ShouldBeFalse();
}
