// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.ForwardedIdentity.for_ForwardedIdentitySigningReport;

public class when_reporting_body_flow_transport : Specification
{
    ForwardedIdentityFlowStatus _signed;
    ForwardedIdentityFlowStatus _unsigned;
    ForwardedIdentityFlowStatus _sharedHost;

    void Because()
    {
        _signed = Row(Config(new(), "https://backend.example"));
        _unsigned = Row(Config(null, "https://backend.example"));
        _sharedHost = Row(Config(null, "https://stage.example"));
    }

    [Fact] void should_report_mutual_tls_when_signing_extends_the_host_set() => _signed.Transport.ShouldEqual(BackendHops.BackendHopTransport.MutualTls);
    [Fact] void should_report_only_tls_for_an_unsigned_external_host() => _unsigned.Transport.ShouldEqual(BackendHops.BackendHopTransport.Tls);
    [Fact] void should_report_mutual_tls_for_an_independently_configured_backend_host() => _sharedHost.Transport.ShouldEqual(BackendHops.BackendHopTransport.MutualTls);
    [Fact] void should_not_report_a_body_envelope() => _signed.IsSigned.ShouldBeFalse();

    static ForwardedIdentityFlowStatus Row(C.AuthProxy config) => ForwardedIdentitySigningReport.For(config).Single(row => row.Flow == ForwardedIdentityFlow.InvitationStage);

    static C.AuthProxy Config(C.ForwardedIdentitySigning? signing, string backend) => new()
    {
        BackendTls = new() { ClientCertificate = new() },
        Services = new Dictionary<string, C.Service> { ["app"] = new() { Backend = new() { BaseUrl = backend }, ForwardedIdentity = signing } },
        Invite = new() { StageUrl = "https://stage.example/stage" }
    };
}
