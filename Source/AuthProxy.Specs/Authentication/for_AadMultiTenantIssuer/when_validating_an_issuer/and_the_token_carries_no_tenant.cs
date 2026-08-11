// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.Authentication.for_AadMultiTenantIssuer.given;
using Microsoft.IdentityModel.Tokens;

namespace Cratis.AuthProxy.Authentication.for_AadMultiTenantIssuer.when_validating_an_issuer;

public class and_the_token_carries_no_tenant : a_token_carrying_a_tenant
{
    Exception _result;

    void Because() => _result = Catch.Exception(() =>
        AadMultiTenantIssuer.Validate(
            $"https://login.microsoftonline.com/{TenantId}/v2.0",
            TokenWithoutTenant(),
            _parameters));

    [Fact] void should_reject_the_issuer() => _result.ShouldBeOfExactType<SecurityTokenInvalidIssuerException>();
}
