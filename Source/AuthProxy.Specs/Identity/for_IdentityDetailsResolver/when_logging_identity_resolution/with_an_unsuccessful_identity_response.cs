// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Net;
using Cratis.AuthProxy.Identity.for_IdentityDetailsResolver.given;

namespace Cratis.AuthProxy.Identity.for_IdentityDetailsResolver.when_logging_identity_resolution;

/// <summary>
/// Specifies that an unsuccessful identity endpoint answer is reported by service and status alone. A
/// downstream error body is unbounded content this proxy neither authored nor inspected, so copying it into
/// a log line publishes whatever the backend happened to put there.
/// </summary>
public class with_an_unsuccessful_identity_response : an_identity_details_resolver_with_recorded_logs
{
    async Task Because() => await CreateResolver(HttpStatusCode.BadGateway, SensitiveResponseBody)
        .Resolve(new DefaultHttpContext(), CanonicalPrincipal(), TenantId);

    [Fact] void should_not_disclose_the_downstream_response_body() => _logger.Text.ShouldNotContain(SensitiveResponseBody);
    [Fact] void should_still_record_the_bounded_reason() => _logger.Text.ShouldContain("502");
}
