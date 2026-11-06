// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.given;

namespace Cratis.AuthProxy.ForwardedIdentity.for_ForwardedIdentitySigningReport;

public class when_startup_reports_on_behalf_calls : Specification
{
    ForwardedIdentitySigningStartupReport _report;
    RecordingLogger<ForwardedIdentitySigningStartupReport> _logger;

    void Establish()
    {
        var config = Substitute.For<IOptionsMonitor<C.AuthProxy>>();
        config.CurrentValue.Returns(new C.AuthProxy
        {
            Services = new Dictionary<string, C.Service> { ["app"] = new() { Backend = new() { BaseUrl = "https://app.example" }, ForwardedIdentity = new() { Audience = "spec-audience", KeyId = "spec-key" } } },
            OnBehalf = new() { Service = "app" }
        });
        _logger = new RecordingLogger<ForwardedIdentitySigningStartupReport>();
        _report = new(config, _logger);
    }

    Task Because() => _report.StartAsync(CancellationToken.None);

    [Fact] void should_describe_the_per_call_attestation() => _logger.Text.ShouldContain("OnBehalf to app: attested, not envelope-signed");
    [Fact] void should_not_report_the_on_behalf_flow_as_unsigned() => _logger.Text.ShouldNotContain("OnBehalf to app: not signed");
    [Fact] void should_report_its_transport() => _logger.Text.ShouldContain("Backend transport for OnBehalf to app: Tls");
}
