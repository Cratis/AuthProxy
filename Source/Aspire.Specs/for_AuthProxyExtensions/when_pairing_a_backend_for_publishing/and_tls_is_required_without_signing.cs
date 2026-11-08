// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Aspire.for_AuthProxyExtensions.when_pairing_a_backend_for_publishing;

public class and_tls_is_required_without_signing : given.an_auth_proxy_being_published
{
    Dictionary<string, object> _proxy;

    async Task Because()
    {
        _api.WithHttpsEndpoint(targetPort: 8443);
        _resource.WithBackend("main", _api, "https").WithRequiredTlsOnIdentityHops();
        _proxy = await RawEnvironmentOf(_resource.Resource);
    }

    [Fact] void should_enable_startup_tls_validation() => _proxy["Cratis__AuthProxy__BackendTls__RequireTlsOnIdentityHops"].ShouldEqual("true");
    [Fact] void should_select_the_https_endpoint() => ((ReferenceExpression)_proxy["Cratis__AuthProxy__Services__main__Backend__BaseUrl"]).ValueExpression.ShouldContain("api.bindings.https.url");
    [Fact] void should_not_enable_signing_implicitly() => _proxy.Keys.Any(key => key.Contains("__ForwardedIdentity", StringComparison.Ordinal)).ShouldBeFalse();
    [Fact] void should_not_select_local_development() => _proxy.ContainsKey("Cratis__AuthProxy__Profile").ShouldBeFalse();
}
