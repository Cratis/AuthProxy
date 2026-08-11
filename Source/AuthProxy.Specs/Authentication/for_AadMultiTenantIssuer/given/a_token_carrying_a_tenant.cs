// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

namespace Cratis.AuthProxy.Authentication.for_AadMultiTenantIssuer.given;

public class a_token_carrying_a_tenant : Specification
{
    protected const string TenantId = "9188040d-6c67-4c5b-b112-36a304b66dad";

    protected TokenValidationParameters _parameters = new();

    protected static JsonWebToken TokenWithTenant(string tenantId) =>
        new("{\"alg\":\"none\"}", $"{{\"tid\":\"{tenantId}\"}}");

    protected static JsonWebToken TokenWithoutTenant() =>
        new("{\"alg\":\"none\"}", "{}");
}
