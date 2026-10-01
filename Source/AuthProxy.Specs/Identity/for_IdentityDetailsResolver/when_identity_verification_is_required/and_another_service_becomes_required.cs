// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Net;

namespace Cratis.AuthProxy.Identity.for_IdentityDetailsResolver.when_identity_verification_is_required;

public class and_another_service_becomes_required : given.an_upgrading_verification_resolver
{
    async Task Establish()
    {
        _config.Session.IdentityResultCacheDuration = TimeSpan.FromMinutes(1);
        _config.Services["reporting"] = new C.Service
        {
            Backend = new C.ServiceEndpoint { BaseUrl = "https://reporting.example.com" },
            IdentityVerification = C.IdentityVerificationMode.BestEffort
        };
        _handler.Respond = (request, _, _) => request.RequestUri!.Host == "reporting.example.com"
            ? throw new HttpRequestException("connection refused")
            : Task.FromResult(Response(HttpStatusCode.OK, PositiveBody));
        await IssueCookieAndUpgrade(C.IdentityVerificationMode.Required);
        _config.Services["reporting"].IdentityVerification = C.IdentityVerificationMode.Required;
    }

    async Task Because() => _result = await _resolver.Resolve(_context, Principal(), TenantId);

    [Fact] void should_have_verified_main_before_the_reload() => _previousResult.IsAuthorized.ShouldBeTrue();
    [Fact] void should_not_reuse_the_cookie_or_result_from_the_old_service_set() => _handler.Calls.ShouldEqual(4);
    [Fact] void should_deny_when_the_new_required_service_does_not_verify() => _result.IsAuthorized.ShouldBeFalse();
    [Fact] void should_name_the_new_required_service() => _logger.Text.ShouldContain("Cratis__AuthProxy__Services__reporting__IdentityVerification=BestEffort");
}
