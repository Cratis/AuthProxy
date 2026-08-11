// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.for_TenancyMiddleware.when_tenant_resolution_fails;

/// <summary>
/// The refusal a deployment with tenant resolutions configured relies on, and the cheapest way there was to
/// ask for it to be waived. A pending-invite cookie suppresses it so an onboarding exchange can run; the
/// cookie's <em>presence</em> used to be the whole test, so an empty value bought the waiver from a caller
/// who had no invite and was going to run no exchange.
/// </summary>
public class and_a_blank_invite_cookie_is_presented : Specification
{
    TenancyMiddleware _middleware;
    DefaultHttpContext _context;
    IErrorPageProvider _errorPages;
    bool _nextCalled;

    void Establish()
    {
        var config = new C.AuthProxy
        {
            TenantResolutions = [new C.TenantResolution { Strategy = C.TenantSourceIdentifierResolverType.Specified }]
        };
        var optionsMonitor = Substitute.For<IOptionsMonitor<C.AuthProxy>>();
        optionsMonitor.CurrentValue.Returns(config);

        var tenantResolver = Substitute.For<ITenantResolver>();
        tenantResolver.TryResolve(Arg.Any<HttpContext>(), out Arg.Any<string>()).Returns(false);

        _errorPages = Substitute.For<IErrorPageProvider>();

        _middleware = new TenancyMiddleware(
            _ =>
            {
                _nextCalled = true;
                return Task.CompletedTask;
            },
            optionsMonitor,
            tenantResolver,
            Substitute.For<ITenantVerifier>(),
            _errorPages,
            Substitute.For<ILogger<TenancyMiddleware>>());

        _context = new DefaultHttpContext
        {
            User = new ClaimsPrincipal(new ClaimsIdentity([new Claim("oid", "user-1")], "aad"))
        };
        _context.Request.Path = "/private";
        _context.Request.Headers.Cookie = $"{Cookies.InviteToken}=";
    }

    async Task Because() => await _middleware.InvokeAsync(_context);

    [Fact] void should_not_forward_the_request() => _nextCalled.ShouldBeFalse();
    [Fact] void should_explain_that_there_is_no_organization() =>
        _errorPages.Received(1).WriteErrorPageAsync(_context, WellKnownPageNames.NoOrganization, StatusCodes.Status403Forbidden);
}
