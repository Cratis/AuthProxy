// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.ForwardedIdentity.for_ForwardingAudiences;

/// <summary>
/// The audience names the service a request is for, so an assertion one backend received cannot be replayed to a
/// sibling. A service's audience is its configuration key unless it states another, and the tenant-selection endpoint
/// borrows the audience of the service that serves it: the one with the same origin and the longest matching base path.
/// </summary>
public class when_resolving_an_audience : Specification
{
    C.AuthProxy _configuration;
    string _byKey;
    string _stated;
    string _unknown;
    string? _tenantsOnTheMostSpecificBackend;
    string? _tenantsOnAnotherPort;
    bool _ambiguous;

    void Establish() => _configuration = new C.AuthProxy
    {
        Services = new Dictionary<string, C.Service>
        {
            ["studio"] = new C.Service { Backend = new C.ServiceEndpoint { BaseUrl = "https://shared.internal" } },
            ["reports"] = new C.Service
            {
                Backend = new C.ServiceEndpoint { BaseUrl = "https://shared.internal/reports/" },
                ForwardingAudience = "reports-api",
            },
        },
    };

    void Because()
    {
        _byKey = ForwardingAudiences.For(_configuration, "studio");
        _stated = ForwardingAudiences.For(_configuration, "reports");
        _unknown = ForwardingAudiences.For(_configuration, "billing");
        _tenantsOnTheMostSpecificBackend = ForwardingAudiences.ForTenantSelection(
            _configuration,
            new SelectionOptions { TenantsEndpoint = "https://shared.internal/reports/api/tenants" },
            out _ambiguous);
        _tenantsOnAnotherPort = ForwardingAudiences.ForTenantSelection(
            _configuration,
            new SelectionOptions { TenantsEndpoint = "https://shared.internal:8443/api/tenants" },
            out _);
    }

    [Fact] void should_default_to_the_service_key() => _byKey.ShouldEqual("studio");
    [Fact] void should_use_the_stated_audience() => _stated.ShouldEqual("reports-api");
    [Fact] void should_use_the_key_of_a_service_it_does_not_know() => _unknown.ShouldEqual("billing");
    [Fact] void should_use_the_service_with_the_longest_matching_base_path() => _tenantsOnTheMostSpecificBackend.ShouldEqual("reports-api");
    [Fact] void should_not_report_the_longest_match_as_ambiguous() => _ambiguous.ShouldBeFalse();
    [Fact] void should_not_match_a_backend_on_another_port() => _tenantsOnAnotherPort.ShouldBeNull();
}
