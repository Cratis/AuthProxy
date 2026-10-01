// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.AccessTokens.for_AccessTokenConfigurationValidator.given;

public class an_access_token_validator : Specification
{
    protected C.Authentication _authentication;
    protected C.Service _service;
    protected ValidateOptionsResult _result;

    void Establish()
    {
        _authentication = new() { OidcProviders = [new() { Name = "Workforce", Authority = "https://login.example.com", ClientId = "client-id" }] };
        _service = new()
        {
            Backend = new C.ServiceEndpoint { BaseUrl = "http://reporting/" },
            AccessToken = new() { Scopes = ["api://reporting/access_as_user"] },
        };
    }

    protected void Validate()
    {
        var monitor = Substitute.For<IOptionsMonitor<C.Authentication>>();
        monitor.CurrentValue.Returns(_authentication);
        _result = new AccessTokenConfigurationValidator(monitor).Validate(null, new C.AuthProxy { Services = new Dictionary<string, C.Service> { ["reporting"] = _service } });
    }
}
