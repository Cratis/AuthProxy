// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Admission.for_CapabilityAdmission;

/// <summary>
/// An oversized body never becomes a presentation, so a caller admitted to nothing cannot make the
/// verifier do work either.
/// </summary>
public class when_the_capability_exceeds_the_bound : given.a_capability_admission
{
    void Establish()
    {
        _config.Admission.Capability!.MaximumLength = 16;
        Presenting(new string('a', 4096));
        VerifierAdmitting();
    }

    async Task Because() => _admitted = await _admission.TryAdmit(_context, _config);

    [Fact] void should_not_admit_the_caller() => _admitted.ShouldBeFalse();
    [Fact] void should_not_ask_the_verifier() => _verifier.DidNotReceiveWithAnyArgs().Verify(default!, default);
    [Fact] void should_issue_no_cookie() => _context.Response.Headers.SetCookie.Count.ShouldEqual(0);
}
