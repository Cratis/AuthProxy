// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.Links.for_LinkCallbackCompletion.given;

namespace Cratis.AuthProxy.Links.for_LinkCallbackCompletion.when_the_exchange_fails;

/// <summary>
/// A tampered return URL must not reach the browser on the failure path either — neither as a
/// <c>Location</c> header nor echoed into the page.
/// </summary>
public class and_the_return_url_is_hostile : a_link_callback_context
{
    string _body;

    protected override LinkExchangeResult ExchangeResult => LinkExchangeResult.Failed;

    protected override string? RecordedReturnUrl => "//evil.test/link";

    async Task Because()
    {
        await LinkCallbackCompletion.Complete(_ticketContext, _properties);
        _body = ResponseBody();
    }

    [Fact] void should_not_send_a_location_header() => _context.Response.Headers.Location.ToString().ShouldEqual(string.Empty);
    [Fact] void should_not_disclose_the_tampered_return_url() => _body.ShouldNotContain("evil.test");
    [Fact] void should_answer_with_a_non_success_status() => _context.Response.StatusCode.ShouldEqual(StatusCodes.Status403Forbidden);
}
