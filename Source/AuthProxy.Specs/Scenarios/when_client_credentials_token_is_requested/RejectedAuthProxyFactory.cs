// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Net;

namespace Cratis.AuthProxy.Scenarios.when_client_credentials_token_is_requested;

public class RejectedAuthProxyFactory : AuthProxyFactory
{
    protected override HttpStatusCode VerificationStatusCode => HttpStatusCode.Unauthorized;
}
