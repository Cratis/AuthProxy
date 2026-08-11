// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Authorization.for_AccessControlMiddleware;

/// <summary>
/// Closing the interactive contract changes nothing about the claim gate. The two are orthogonal: admission
/// decides whether a caller who presented nothing is answered at all, and this gate decides who a signed-in
/// caller has to be — so a caller with no session is still left to the machinery that already refuses them.
/// <para>
/// A sibling rather than an edit to <c>when_the_caller_has_no_session</c>, because that spec states the
/// behavior of every deployment and must keep stating it unchanged. This one states that the new mode did
/// not quietly reach into it.
/// </para>
/// </summary>
public class when_the_caller_has_no_session_and_the_deployment_is_closed : given.an_access_control_middleware
{
    void Establish()
    {
        _config.Admission = new C.Admission
        {
            Mode = C.AdmissionMode.CapabilityOnly,
            Capability = new C.AdmissionCapability { VerifierUrl = "https://verifier.test/admit" },
        };

        BuildMiddleware();
    }

    async Task Because() => await _middleware.InvokeAsync(_context);

    [Fact] void should_leave_the_request_to_the_rest_of_the_pipeline() => _nextCalled.ShouldBeTrue();
    [Fact] void should_not_write_an_error_page() => _errorPageProvider.DidNotReceiveWithAnyArgs().WriteErrorPageAsync(default!, default!, default);
}
