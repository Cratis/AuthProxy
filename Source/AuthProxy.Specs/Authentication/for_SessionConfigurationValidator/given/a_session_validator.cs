// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Authentication.for_SessionConfigurationValidator.given;

public class a_session_validator : Specification
{
    protected C.AuthProxy _config;
    protected ValidateOptionsResult _result;

    void Establish() => _config = new();

    protected static C.Service Routable(params string[] hosts) => new()
    {
        Hosts = hosts,
        Backend = new C.ServiceEndpoint { BaseUrl = "http://backend/" },
    };

    protected void Validate() => _result = new SessionConfigurationValidator().Validate(null, _config);

    protected bool Reports(string fragment) => _result.Failures?.Any(_ => _.Contains(fragment)) == true;
}
