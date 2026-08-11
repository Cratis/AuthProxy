// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Admission.for_CapabilityAdmission;

/// <summary>
/// A capability arrives in a body, and only a request that has one is a presentation. Anything else on the
/// admission path is an ordinary unadmitted request.
/// </summary>
public class when_the_method_is_not_a_post : given.a_capability_admission
{
    void Establish()
    {
        _context.Request.Method = HttpMethods.Get;
        Presenting(Capability);
        VerifierAdmitting();
    }

    async Task Because() => _admitted = await _admission.TryAdmit(_context, _config);

    [Fact] void should_not_admit_the_caller() => _admitted.ShouldBeFalse();
    [Fact] void should_not_ask_the_verifier() => _verifier.DidNotReceiveWithAnyArgs().Verify(default!, default);
}
