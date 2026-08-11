// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.Authentication.for_AadMultiTenantIssuer.given;

namespace Cratis.AuthProxy.Authentication.for_AadMultiTenantIssuer.when_validating_an_issuer;

public class and_it_is_the_v1_issuer_for_the_tokens_tenant : a_token_carrying_a_tenant
{
    const string Issuer = $"https://sts.windows.net/{TenantId}/";
    string _result;

    void Because() => _result = AadMultiTenantIssuer.Validate(Issuer, TokenWithTenant(TenantId), _parameters);

    [Fact] void should_accept_the_issuer() => _result.ShouldEqual(Issuer);
}
