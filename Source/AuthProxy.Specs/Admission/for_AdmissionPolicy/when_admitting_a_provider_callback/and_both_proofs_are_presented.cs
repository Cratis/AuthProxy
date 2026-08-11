// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Admission.for_AdmissionPolicy.when_admitting_a_provider_callback;

/// <summary>
/// A provider handing a caller back is admitted when the browser carries both proofs: AuthProxy's own
/// record that it was admitted, and the framework's own record that a handshake is in flight.
/// </summary>
public class and_both_proofs_are_presented : given.an_admission_policy
{
    bool _isAdmitted;

    void Establish()
    {
        _context.Request.Path = "/signin-github";
        Presenting(
            $"{Cookies.EntryTransaction}={SealedTransaction(TimeSpan.FromMinutes(10))}",
            $"{Cookies.CorrelationPrefix}abc123=N");
    }

    void Because() => _isAdmitted = _policy.IsAdmitted(_context, _config);

    [Fact] void should_admit_the_callback() => _isAdmitted.ShouldBeTrue();
}
