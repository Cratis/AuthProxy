// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Admission.for_AdmissionPolicy.when_admitting_a_provider_callback;

/// <summary>
/// Being mid-handshake is not being admitted either. The correlation cookie is written by the framework
/// for anyone who reaches a challenge, so treating it as sufficient would make the callback path the one
/// way in that never asked for a capability.
/// </summary>
public class and_the_entry_transaction_is_missing : given.an_admission_policy
{
    bool _isAdmitted;

    void Establish()
    {
        _context.Request.Path = "/signin-github";
        Presenting($"{Cookies.CorrelationPrefix}abc123=N");
    }

    void Because() => _isAdmitted = _policy.IsAdmitted(_context, _config);

    [Fact] void should_not_admit_the_callback() => _isAdmitted.ShouldBeFalse();
}
