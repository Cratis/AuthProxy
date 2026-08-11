// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Admission.for_CapabilityAdmission;

/// <summary>
/// A refused presentation leaves nothing behind at all — no cookie, and no status of its own for the caller
/// to read the refusal off.
/// </summary>
public class when_the_capability_is_refused : given.a_capability_admission
{
    void Establish() => Presenting(Capability);

    async Task Because() => _admitted = await _admission.TryAdmit(_context, _config);

    [Fact] void should_not_admit_the_caller() => _admitted.ShouldBeFalse();
    [Fact] void should_issue_no_cookie() => _context.Response.Headers.SetCookie.Count.ShouldEqual(0);
}
