// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.Links.for_LinkCallbackCompletion.given;

namespace Cratis.AuthProxy.Links.for_LinkCallbackCompletion.when_the_exchange_fails;

/// <summary>
/// A failed exchange must not be answered with the completion redirect. In five of the six ways the exchange
/// can fail the application is never contacted, so it holds no record of the attempt — the redirect is the
/// only signal it and the person ever get, and reporting success there is reporting a credential link that
/// does not exist.
/// </summary>
public class and_a_return_url_was_recorded : a_link_callback_context
{
    string _body;

    protected override LinkExchangeResult ExchangeResult => LinkExchangeResult.Failed;

    async Task Because()
    {
        await LinkCallbackCompletion.Complete(_ticketContext, _properties);
        _body = ResponseBody();
    }

    [Fact] void should_not_redirect_to_the_return_url() => _context.Response.Headers.Location.ToString().ShouldNotContain(ReturnUrl);
    [Fact] void should_not_send_a_location_header() => _context.Response.Headers.Location.ToString().ShouldEqual(string.Empty);
    [Fact] void should_answer_with_a_non_success_status() => _context.Response.StatusCode.ShouldEqual(StatusCodes.Status403Forbidden);
    [Fact] void should_write_a_generic_failure_page() => _body.ShouldContain("Link Not Completed");
    [Fact] void should_not_disclose_the_link_token() => _body.ShouldNotContain(LinkToken);
    [Fact] void should_not_disclose_the_provider_subject() => _body.ShouldNotContain(ProviderSubject);
    [Fact] void should_handle_the_response() => _ticketContext.Result.Handled.ShouldBeTrue();
}
