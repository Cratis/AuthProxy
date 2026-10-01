// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.ReverseProxy.for_ServiceRoutingConfigurationValidator;

public class when_services_are_told_apart_by_host_and_prefix : given.a_service_routing_validator
{
    void Establish()
    {
        var tenantReports = Routable("tenant.example.com");
        tenantReports.PathPrefix = "/reports";
        _services["tenant-reports"] = tenantReports;

        var reports = Routable();
        reports.PathPrefix = "/reports/";
        reports.StripPathPrefix = true;
        _services["reports"] = reports;

        _services["billing"] = Routable("billing.example.com", "billing.example.com:8443");
        _services["portal"] = Routable();
    }

    void Because() => Validate();

    [Fact] void should_succeed() => _result.Succeeded.ShouldBeTrue();
}
