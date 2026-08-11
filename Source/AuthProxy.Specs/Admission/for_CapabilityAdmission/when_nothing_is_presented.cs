// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Admission.for_CapabilityAdmission;

/// <summary>
/// An empty body is not a capability, and asking the verifier about one would let an unadmitted caller
/// drive traffic into the deployment's own service.
/// </summary>
public class when_nothing_is_presented : given.a_capability_admission
{
    void Establish()
    {
        Presenting(string.Empty);
        VerifierAdmitting();
    }

    async Task Because() => _admitted = await _admission.TryAdmit(_context, _config);

    [Fact] void should_not_admit_the_caller() => _admitted.ShouldBeFalse();
    [Fact] void should_not_ask_the_verifier() => _verifier.DidNotReceiveWithAnyArgs().Verify(default!, default);
}
