// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Identity.for_IdentityMiddleware.when_identity_is_denied;

/// <summary>
/// When the provider of the session cannot be determined the denial fails closed to the existing forbidden page.
/// </summary>
public class and_the_session_records_no_provider : given.an_identity_middleware
{
    void Establish()
    {
        ResolveTenant();
        _authentication.OidcProviders = [new C.OidcProvider { Name = "Microsoft", DenialResponse = C.OidcDenialResponse.FailedSignIn }];
        DenyIdentity();
    }

    async Task Because() => await _middleware.InvokeAsync(_context);

    [Fact] void should_refuse_with_the_forbidden_page() => ShouldHaveBeenRefused();
    [Fact] void should_not_forward_the_request() => _nextCalled.ShouldBeFalse();
}
