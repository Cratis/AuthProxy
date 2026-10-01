// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Identity.for_IdentityAuthorizationCache.when_recording_with_verification_required;

public class and_only_some_services_verified : given.a_verifying_deployment
{
    bool _authorized;

    void Establish() => _configuration.Services["reporting"] = new C.Service
    {
        Backend = new C.ServiceEndpoint { BaseUrl = "https://reporting.example.com" },
        IdentityVerification = C.IdentityVerificationMode.Required
    };

    void Because()
    {
        var principal = new ClientPrincipal { UserId = "user-1" };
        _cache.Record(_context, principal, TenantId, ["main"]);
        var cookie = _context.Response.Headers.SetCookie.Single(_ => _.StartsWith($"{Cookies.IdentityAuthorization}=", StringComparison.Ordinal));
        var request = new DefaultHttpContext();
        request.Request.Headers.Cookie = cookie.Split(';', 2)[0];
        _authorized = _cache.IsAuthorized(request, principal, TenantId);
    }

    [Fact] void should_not_infer_verification_of_reporting_from_current_configuration() => _authorized.ShouldBeFalse();
}
