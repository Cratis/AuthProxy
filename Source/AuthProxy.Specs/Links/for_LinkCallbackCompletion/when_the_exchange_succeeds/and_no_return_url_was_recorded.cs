// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.Links.for_LinkCallbackCompletion.given;

namespace Cratis.AuthProxy.Links.for_LinkCallbackCompletion.when_the_exchange_succeeds;

public class and_no_return_url_was_recorded : a_link_callback_context
{
    protected override string? RecordedReturnUrl => null;

    async Task Because() => await LinkCallbackCompletion.Complete(_ticketContext, _properties);

    [Fact] void should_redirect() => _context.Response.StatusCode.ShouldEqual(StatusCodes.Status302Found);
    [Fact] void should_redirect_to_the_completion_page() =>
        _context.Response.Headers.Location.ToString().ShouldEqual(WellKnownPaths.LinkComplete);
}
