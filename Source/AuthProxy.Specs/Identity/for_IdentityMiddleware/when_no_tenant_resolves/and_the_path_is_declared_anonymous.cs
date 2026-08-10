// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Identity.for_IdentityMiddleware.when_no_tenant_resolves;

/// <summary>
/// The one deliberate exemption, pinned so it stays deliberate. A path a service lists in
/// <c>AnonymousPaths</c> is declared to be served without a session at all — a magic-link landing page, a
/// signed-token report, a public webhook receiver — so demanding an identity verdict for it would refuse
/// exactly what the declaration exists to permit. The application stays responsible for authorizing those
/// paths, which is what the setting already says.
/// </summary>
public class and_the_path_is_declared_anonymous : given.an_identity_middleware
{
    const string AnonymousPath = "/public";

    void Establish()
    {
        _service.AnonymousPaths = [AnonymousPath];
        _context.Request.Path = AnonymousPath;
    }

    async Task Because() => await _middleware.InvokeAsync(_context);

    [Fact] void should_forward_the_request() => _nextCalled.ShouldBeTrue();
    [Fact] void should_not_refuse_it() =>
        _errorPages.DidNotReceive().WriteErrorPageAsync(Arg.Any<HttpContext>(), Arg.Any<string>(), Arg.Any<int>());
}
