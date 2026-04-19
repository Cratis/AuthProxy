// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Authentication.for_SelectProviderMiddleware.when_multiple_providers_are_configured;

public class and_request_is_made : when_multiple_providers_are_configured
{
    [Fact]
    void should_serve_select_provider_page() =>
        _errorPageProvider.Received(1).WriteErrorPageAsync(
            _context,
            WellKnownPageNames.SelectProvider,
            StatusCodes.Status200OK);

    [Fact]
    void should_set_providers_cookie() =>
        _context.Response.Headers.SetCookie.ToString()
            .ShouldContain(Cookies.Providers);
}
