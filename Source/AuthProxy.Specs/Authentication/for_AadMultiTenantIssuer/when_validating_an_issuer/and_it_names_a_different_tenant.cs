// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.Authentication.for_AadMultiTenantIssuer.given;
using Microsoft.IdentityModel.Tokens;

namespace Cratis.AuthProxy.Authentication.for_AadMultiTenantIssuer.when_validating_an_issuer;

public class and_it_names_a_different_tenant : a_token_carrying_a_tenant
{
    Exception _result;

    void Because() => _result = Catch.Exception(() =>
        AadMultiTenantIssuer.Validate(
            "https://login.microsoftonline.com/11111111-2222-3333-4444-555555555555/v2.0",
            TokenWithTenant(TenantId),
            _parameters));

    [Fact] void should_reject_the_issuer() => _result.ShouldBeOfExactType<SecurityTokenInvalidIssuerException>();
}
