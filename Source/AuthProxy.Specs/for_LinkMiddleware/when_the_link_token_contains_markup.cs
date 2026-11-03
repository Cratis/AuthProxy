// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.for_LinkMiddleware;

public class when_the_link_token_contains_markup : given.a_link_page_context
{
    const string Markup = "\"><script>alert(1)</script>";

    string _body;

    void Establish()
    {
        _context.Request.Path = $"{WellKnownPaths.Link}/github";
        _context.Request.QueryString = QueryString.Create(new Dictionary<string, string?>
        {
            ["returnUrl"] = Markup,
            ["token"] = Markup,
        });
    }

    async Task Because()
    {
        await _middleware.InvokeAsync(_context);
        _body = ResponseBody();
    }

    [Fact] void should_not_write_the_raw_value() => _body.ShouldNotContain("<script>alert(1)");
    [Fact] void should_write_the_encoded_value() => _body.ShouldContain("&quot;&gt;&lt;script&gt;alert(1)");
}
