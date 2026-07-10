// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Scenarios.when_client_credentials_token_is_requested;

public class TenantAuthProxyFactory : AuthProxyFactory
{
    public const string VerifiedTenant = "acme";

    protected override object? VerificationResponseBody => new { tenant = VerifiedTenant };
}
