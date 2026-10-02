// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.Authentication;
using Microsoft.AspNetCore.Authentication;

namespace Cratis.AuthProxy.for_TenantSelectionMiddleware.given;

public class an_invalid_canonical_session : a_tenant_selection_endpoint
{
    protected IAuthenticationService _authenticationService;

    void Establish()
    {
        _authenticationService = Substitute.For<IAuthenticationService>();
        var canonicalIdentityResolver = Substitute.For<ICanonicalIdentityResolver>();
        canonicalIdentityResolver.Resolve(Arg.Any<ClaimsPrincipal>(), Arg.Any<string?>(), Arg.Any<string?>(), Arg.Any<bool>())
            .Returns(CanonicalIdentityResolution.Failed());

        var services = Substitute.For<IServiceProvider>();
        services.GetService(typeof(IAuthenticationService)).Returns(_authenticationService);
        services.GetService(typeof(ICanonicalIdentityResolver)).Returns(canonicalIdentityResolver);
        _context.RequestServices = services;
    }
}
