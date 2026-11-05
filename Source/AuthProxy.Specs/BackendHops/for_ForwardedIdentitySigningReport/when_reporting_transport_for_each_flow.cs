// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.ForwardedIdentity;

namespace Cratis.AuthProxy.BackendHops.for_ForwardedIdentitySigningReport;

public class when_reporting_transport_for_each_flow
{
    [Theory]
    [InlineData(false, false, BackendHopTransport.PlainHttp)]
    [InlineData(true, false, BackendHopTransport.Tls)]
    [InlineData(true, true, BackendHopTransport.MutualTls)]
    public void should_report_the_effective_transport_on_every_identity_flow(bool https, bool client, BackendHopTransport transport)
    {
        var address = https ? "https://backend.example" : "http://backend.example";
        var config = new C.AuthProxy
        {
            BackendTls = new() { ClientCertificate = client ? new() : null },
            Services = new Dictionary<string, C.Service> { ["app"] = new() { Backend = new() { BaseUrl = address }, ForwardedIdentity = new(), BearerRoutes = [new() { PathPrefix = "/tools" }] } },
            TenantResolutions = [new() { Strategy = C.TenantSourceIdentifierResolverType.Selection, Options = new SelectionOptions { TenantsEndpoint = address, ForwardedIdentity = new() } }]
        };
        var rows = ForwardedIdentitySigningReport.For(config);
        rows.Count.ShouldEqual(4);
        rows.All(row => row.Transport == transport).ShouldBeTrue();
        rows.All(row => row.IsSigned).ShouldBeTrue();
    }
}
