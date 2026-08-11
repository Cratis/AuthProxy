// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Admission.for_AdmissionPolicy.when_admitting_a_provider_callback;

/// <summary>
/// Being admitted is not being mid-handshake. A callback arriving on an admitted browser that started no
/// handshake is refused, so the entry transaction alone is not a standing invitation to post whatever a
/// provider callback accepts.
/// </summary>
public class and_the_handshake_proof_is_missing : given.an_admission_policy
{
    bool _isAdmitted;

    void Establish()
    {
        _context.Request.Path = "/signin-github";
        Presenting($"{Cookies.EntryTransaction}={SealedTransaction(TimeSpan.FromMinutes(10))}");
    }

    void Because() => _isAdmitted = _policy.IsAdmitted(_context, _config);

    [Fact] void should_not_admit_the_callback() => _isAdmitted.ShouldBeFalse();
}
