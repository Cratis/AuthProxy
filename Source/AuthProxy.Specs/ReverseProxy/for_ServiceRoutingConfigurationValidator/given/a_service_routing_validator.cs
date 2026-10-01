// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.ReverseProxy.for_ServiceRoutingConfigurationValidator.given;

public class a_service_routing_validator : Specification
{
    protected Dictionary<string, C.Service> _services;
    protected ValidateOptionsResult _result;

    void Establish() => _services = [];

    protected static C.Service Routable(params string[] hosts) => new()
    {
        Hosts = hosts,
        Backend = new C.ServiceEndpoint { BaseUrl = "http://backend/" },
    };

    protected void Validate() => _result = new ServiceRoutingConfigurationValidator().Validate(null, new C.AuthProxy { Services = _services });
}
