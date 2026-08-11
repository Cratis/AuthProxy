// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

namespace Cratis.AuthProxy.Authentication.for_AuthenticationServiceCollectionExtensions.given;

public class an_ingress_authentication_builder : Specification
{
    protected OpenIdConnectOptions _options;

    protected virtual IDictionary<string, string?> Configuration => new Dictionary<string, string?>();

    protected OpenIdConnectOptions ResolveOidcOptions(string scheme)
    {
        var builder = WebApplication.CreateBuilder();
        builder.Configuration.AddInMemoryCollection(Configuration);
        builder.AddIngressAuthentication();

        using var services = builder.Services.BuildServiceProvider();
        return services.GetRequiredService<IOptionsMonitor<OpenIdConnectOptions>>().Get(scheme);
    }
}
