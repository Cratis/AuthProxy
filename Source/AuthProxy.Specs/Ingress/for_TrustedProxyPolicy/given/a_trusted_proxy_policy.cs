// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Ingress.for_TrustedProxyPolicy.given;

public class a_trusted_proxy_policy : Specification
{
    protected AuthProxy.Ingress.TrustedProxyPolicy _policy;

    protected virtual C.Ingress Ingress => new();

    void Establish() => _policy = new(Options.Create(Ingress));
}
