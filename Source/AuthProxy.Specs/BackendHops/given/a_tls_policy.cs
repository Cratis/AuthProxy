// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.Extensions.Logging.Abstractions;

namespace Cratis.AuthProxy.BackendHops.given;

public class a_tls_policy : Specification
{
    protected TestCertificates certificates;
    protected C.AuthProxy configuration;
    protected IOptionsMonitor<C.AuthProxy> monitor;
    private protected BackendTlsMaterialSource source;
    private protected BackendTlsHttpClientPolicy policy;

    void Establish()
    {
        certificates = new();
        configuration = new()
        {
            BackendTls = certificates.Settings,
            Services = new Dictionary<string, C.Service> { ["app"] = new() { Backend = new() { BaseUrl = "https://localhost" }, Frontend = new() { BaseUrl = "https://frontend.example" } } }
        };
        monitor = Substitute.For<IOptionsMonitor<C.AuthProxy>>();
        monitor.CurrentValue.Returns(_ => configuration);
        source = new(monitor, TimeProvider.System, NullLogger<BackendTlsMaterialSource>.Instance);
        policy = new(monitor, source, NullLogger<BackendTlsHttpClientPolicy>.Instance);
    }

    void Destroy() => certificates.Dispose();
}
