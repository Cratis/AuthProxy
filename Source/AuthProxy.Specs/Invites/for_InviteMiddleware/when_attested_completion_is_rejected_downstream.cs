// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Net;
using Cratis.AuthProxy.Invites.for_InviteMiddleware.given;

namespace Cratis.AuthProxy.Invites.for_InviteMiddleware;

public class when_attested_completion_is_rejected_downstream : an_attested_invite_completion
{
    async Task Because()
    {
        _handler.StatusCode = HttpStatusCode.BadRequest;
        await _middleware.InvokeAsync(_context);
    }

    [Fact] void should_not_continue_the_pipeline() => _nextCalled.ShouldBeFalse();
    [Fact] void should_serve_a_branded_denial() => _errorPageProvider.Received(1).WriteErrorPageAsync(_context, WellKnownPageNames.InvitationInvalid, StatusCodes.Status403Forbidden);
}
