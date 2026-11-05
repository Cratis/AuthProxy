// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Aspire.for_AuthProxyExtensions.when_pairing_a_backend;

public class and_the_tenant_list_is_on_an_unpaired_resource : given.an_auth_proxy_and_a_backend
{
    Dictionary<string, string> _environment;

    async Task Because()
    {
        var tenants = _builder.AddContainer("tenants", "example/tenants");
        _resource.WithSelectionTenantResolution(tenants, "/tenants").WithSignedForwardingTo(_api);
        _environment = await EnvironmentOf(_resource.Resource);
    }

    [Fact] void should_not_sign_the_unpaired_tenant_list() => _environment.Keys.Any(key => key.Contains("__Options__ForwardedIdentity", StringComparison.Ordinal)).ShouldBeFalse();
}
