// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.for_LinkMiddleware;

public class when_a_link_is_requested_with_get : given.a_link_page_context
{
    string _body;

    void Establish()
    {
        _context.Request.Path = $"{WellKnownPaths.Link}/github";
        _context.Request.QueryString = QueryString.Create(new Dictionary<string, string?>
        {
            ["returnUrl"] = "/settings/link-complete",
            ["token"] = "the-link-token",
        });
    }

    async Task Because()
    {
        await _middleware.InvokeAsync(_context);
        _body = ResponseBody();
    }

    [Fact] void should_not_challenge() => _authenticationService.DidNotReceiveWithAnyArgs().ChallengeAsync(default!, default, default);
    [Fact] void should_answer_ok() => _context.Response.StatusCode.ShouldEqual(StatusCodes.Status200OK);
    [Fact] void should_post_the_form_to_the_provider_path() => _body.ShouldContain("action=\"/.cratis/link/github\"");
    [Fact] void should_name_the_provider() => _body.ShouldContain("GitHub");
    [Fact] void should_carry_the_link_token() => _body.ShouldContain("the-link-token");
    [Fact] void should_carry_the_antiforgery_field() => _body.ShouldContain($"name=\"{ProxyAntiforgery.FormFieldName}\" value=\"{RequestToken}\"");
    [Fact] void should_deny_framing() => _context.Response.Headers.XFrameOptions.ToString().ShouldEqual("DENY");
}
