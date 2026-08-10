// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Net;
using Cratis.AuthProxy.Identity.for_IdentityDetailsResolver.given;

namespace Cratis.AuthProxy.Identity.for_IdentityDetailsResolver.when_logging_identity_resolution;

/// <summary>
/// A denial has to be diagnosable, and the tempting way to make it so is to log what the service actually
/// answered — which is a response body from a system that knows exactly who the caller is. The reason
/// travels as a closed enumeration instead, so the log names the failure without publishing anything the
/// service said about the person behind it.
/// </summary>
public class with_a_required_verification_denial : an_identity_details_resolver_with_recorded_logs
{
    async Task Because() =>
        await CreateResolver(HttpStatusCode.BadGateway, SensitiveResponseBody, C.IdentityVerificationMode.Required)
            .Resolve(new DefaultHttpContext(), CanonicalPrincipal(), TenantId);

    [Fact] void should_record_a_bounded_reason_code() => _logger.Text.ShouldContain(nameof(IdentityVerificationReason.UnsuccessfulStatusCode));
    [Fact] void should_not_disclose_the_downstream_response_body() => _logger.Text.ShouldNotContain(SensitiveResponseBody);
    [Fact] void should_not_disclose_the_canonical_identity() => ShouldNotContainCanonicalIdentity();
}
