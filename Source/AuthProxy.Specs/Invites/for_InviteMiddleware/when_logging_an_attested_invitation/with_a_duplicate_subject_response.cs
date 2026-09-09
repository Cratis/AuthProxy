// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Net;

namespace Cratis.AuthProxy.Invites.for_InviteMiddleware.when_logging_an_attested_invitation;

/// <summary>
/// The exchange endpoint answers <c language="text">409</c>: the attested subject already belongs to a user. The attested
/// protocol records that collision exactly as the legacy exchange does, and the backend's response body -
/// whatever it happens to carry - is never part of the record.
/// </summary>
public class with_a_duplicate_subject_response : given.an_attested_invite_completion
{
    const string BackendResponseBody = "{\"conflictingUser\":\"sensitive-backend-detail\"}";

    async Task Because()
    {
        _handler.StatusCode = HttpStatusCode.Conflict;
        _handler.ResponseBody = BackendResponseBody;

        await _middleware.InvokeAsync(_context);
    }

    [Fact] void should_record_the_collision() => _logger.Text.ShouldContain("already associated with an existing user");
    [Fact] void should_not_disclose_the_backend_response_body() => _logger.Text.ShouldNotContain("sensitive-backend-detail");
    [Fact] void should_not_disclose_the_provider_subject() => _logger.Text.ShouldNotContain("provider-subject");
    [Fact] void should_not_claim_the_invitation_was_exchanged() => _logger.Text.ShouldNotContain("Invite exchanged successfully");
    [Fact] void should_not_continue_the_pipeline() => _nextCalled.ShouldBeFalse();
}
