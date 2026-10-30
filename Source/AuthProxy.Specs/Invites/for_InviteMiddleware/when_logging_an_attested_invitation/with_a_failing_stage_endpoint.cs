// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Net;

namespace Cratis.AuthProxy.Invites.for_InviteMiddleware.when_logging_an_attested_invitation;

public class with_a_failing_stage_endpoint : given.an_attested_invitation_staging
{
    void Establish() => _handler.StatusCode = HttpStatusCode.InternalServerError;

    async Task Because() => await ((InviteMiddleware)_context.Items["middleware"]).InvokeAsync(_context);

    [Fact] void should_record_the_endpoint_status() => _logger.Text.ShouldContain("Invite exchange endpoint returned 500");
    [Fact] void should_answer_invitation_invalid() => _errorPages.Received(1).WriteErrorPageAsync(_context, WellKnownPageNames.InvitationInvalid, StatusCodes.Status401Unauthorized);
}
