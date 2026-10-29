// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Net;
using Microsoft.AspNetCore.Authentication;

namespace Cratis.AuthProxy.for_TenantSelectionMiddleware;

public class when_selecting_a_tenant_for_an_identity_without_a_stable_account : given.a_tenant_selection_endpoint
{
    IAuthenticationService _authenticationService;

    void Establish()
    {
        _authenticationService = Substitute.For<IAuthenticationService>();
        var services = Substitute.For<IServiceProvider>();
        services.GetService(typeof(IAuthenticationService)).Returns(_authenticationService);
        _context.RequestServices = services;
        _endpointStatus = HttpStatusCode.OK;
        _endpointBody = """[{"id":"tenant-a","name":"Tenant A"}]""";
        _context.Request.Path = WellKnownPaths.SelectTenant;
        _context.Request.QueryString = new QueryString("?tenantId=tenant-a");
        _context.User = new ClaimsPrincipal(new ClaimsIdentity([new Claim("oid", " untrimmed-user ")], "aad"));
    }

    async Task Because() => await _middleware.InvokeAsync(_context);

    [Fact] void should_not_set_a_selected_tenant_cookie() => _context.Response.Headers.SetCookie.ToString().ShouldNotContain($"{Cookies.Tenant}=tenant-a");
    [Fact] void should_end_the_session() => _authenticationService.Received(1).SignOutAsync(_context, Arg.Any<string?>(), Arg.Any<AuthenticationProperties?>());
    [Fact] void should_not_forward_the_request() => _nextCalled.ShouldBeFalse();
}
