// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Identity.for_IdentityMiddleware.when_no_tenant_resolves;

/// <summary>
/// The refusal belongs to the fail-closed mode and to nothing else. An enrichment deployment has no verdict
/// to be deprived of, so a tenant-less request is carried on with exactly as before — refusing it would break
/// every tenant-less flow in every deployment that never asked for verification.
/// </summary>
public class and_verification_is_not_required : given.an_identity_middleware
{
    void Establish() => _service.IdentityVerification = C.IdentityVerificationMode.BestEffort;

    async Task Because() => await _middleware.InvokeAsync(_context);

    [Fact] void should_forward_the_request() => _nextCalled.ShouldBeTrue();
    [Fact] void should_not_refuse_it() =>
        _errorPages.DidNotReceive().WriteErrorPageAsync(Arg.Any<HttpContext>(), Arg.Any<string>(), Arg.Any<int>());
}
