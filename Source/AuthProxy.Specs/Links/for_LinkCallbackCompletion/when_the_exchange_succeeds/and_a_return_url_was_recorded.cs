// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.Links.for_LinkCallbackCompletion.given;

namespace Cratis.AuthProxy.Links.for_LinkCallbackCompletion.when_the_exchange_succeeds;

/// <summary>
/// The successful answer is the one the application already depends on, so it must stay exactly what it was
/// before the failure path existed: a bare redirect to the return URL the challenge recorded.
/// </summary>
public class and_a_return_url_was_recorded : a_link_callback_context
{
    async Task Because() => await LinkCallbackCompletion.Complete(_ticketContext, _properties);

    [Fact] void should_redirect() => _context.Response.StatusCode.ShouldEqual(StatusCodes.Status302Found);
    [Fact] void should_redirect_to_the_recorded_return_url() => _context.Response.Headers.Location.ToString().ShouldEqual(ReturnUrl);
    [Fact] void should_not_write_a_body() => ResponseBody().ShouldEqual(string.Empty);
    [Fact] void should_handle_the_response() => _ticketContext.Result.Handled.ShouldBeTrue();
    [Fact] async Task should_exchange_the_subject_with_the_application() =>
        await _exchanger.Received(1).Exchange(Arg.Any<ClaimsPrincipal>(), _properties, Arg.Any<string?>());
}
