// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.Arc.Identity;
using Microsoft.AspNetCore.DataProtection;

namespace Cratis.AuthProxy.Identity.for_IdentityDetailsResolver.when_identity_verification_is_required.given;

public class an_upgrading_verification_resolver : a_required_verification_resolver
{
    protected IdentityProviderResult _previousResult;
    protected IdentityProviderResult _result;

    void Establish()
    {
        _config.Session.IdentityResultCacheDuration = TimeSpan.Zero;
        var configuration = Substitute.For<IOptionsMonitor<C.AuthProxy>>();
        configuration.CurrentValue.Returns(_ => _config);
        var keys = new EphemeralDataProtectionProvider();
        _authorizationCache = new IdentityAuthorizationCache(keys, configuration, Substitute.For<ILogger<IdentityAuthorizationCache>>());
        var clients = Substitute.For<IHttpClientFactory>();
        clients.CreateClient(Arg.Any<string>()).Returns(_ => new HttpClient(_handler, disposeHandler: false));
        _resolver = new IdentityDetailsResolver(configuration, clients, [], _memoryCache, _authorizationCache, _logger);
    }

    protected async Task IssueCookieAndUpgrade(C.IdentityVerificationMode issuedUnder)
    {
        _service.IdentityVerification = issuedUnder;
        var issuingContext = new DefaultHttpContext();
        _previousResult = await _resolver.Resolve(issuingContext, Principal(), TenantId);
        var cookie = issuingContext.Response.Headers.SetCookie.Single(_ => _.StartsWith($"{Cookies.IdentityAuthorization}=", StringComparison.Ordinal));
        _context.Request.Headers.Cookie = cookie.Split(';', 2)[0];

        // The same Data Protection keys remain available after upgrading to an unstated (Required) mode.
        _config.Services["main"] = new C.Service { Backend = _service.Backend };
    }
}
