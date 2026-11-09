// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.DependencyInjection;

namespace Cratis.AuthProxy.Authentication.for_SchemeSelection;

public class when_a_bearer_has_been_selected : Specification
{
    string _first;
    string _second;

    void Because()
    {
        var builder = WebApplication.CreateBuilder();
        builder.AddIngressConfiguration();
        builder.AddIngressAuthentication();
        using var services = builder.Services.BuildServiceProvider();
        var selector = services.GetRequiredService<IOptionsMonitor<PolicySchemeOptions>>()
            .Get(ClientCredentialsDefaults.CompositeAuthenticationScheme).ForwardDefaultSelector!;
        var context = new DefaultHttpContext { RequestServices = services };
        context.Request.Headers.Authorization = "Bearer invalid-spec-token";
        _first = selector(context)!;
        context.Request.Headers.Remove("Authorization");
        _second = selector(context)!;
    }

    [Fact] void should_select_bearer_authentication() => _first.ShouldEqual(ClientCredentialsDefaults.AuthenticationScheme);
    [Fact] void should_retain_the_original_selection() => _second.ShouldEqual(_first);
}
