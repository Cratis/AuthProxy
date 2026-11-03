// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy;
using Cratis.AuthProxy.ApplicationContract;
using Cratis.AuthProxy.Authentication;
using Cratis.AuthProxy.Authorization;
using Cratis.AuthProxy.Grpc;
using Cratis.AuthProxy.Identity;
using Cratis.AuthProxy.Invites;
using Cratis.AuthProxy.Links;
using Cratis.AuthProxy.Management;
using Cratis.AuthProxy.ReverseProxy;
using Cratis.AuthProxy.SignIns;
using Cratis.AuthProxy.Tenancy;

var builder = WebApplication.CreateBuilder(args);

builder.Configuration.AddEnvironmentVariables();

try
{
    builder.AddApplicationContract();
}
catch (ApplicationContractException exception)
{
    // A configuration mistake is reported by name and exits; the message never carries a value.
    await Console.Error.WriteLineAsync($"AuthProxy cannot start: {exception.Message}");
    return 78;
}

builder.AddIngressConfiguration();
builder.AddIngressAuthentication();
builder.AddIngressAuthorization();
builder.AddTenancy();
builder.AddIdentityResolution();
builder.AddInvites();
builder.AddLinks();
builder.AddSignIns();
builder.SetupReverseProxy();
builder.AddManagement();
builder.AddGrpcListener();

var app = builder.Build();

// Wrap even the management listener's early answers; this adds no routes or authentication decisions.
app.UseSearchIndexingHeaders();

// First, so a request on the private management listener is answered before authentication, tenancy or the
// reverse proxy can see it — and so a request for a management path on the public listener is refused
// before anything else can serve it.
app.UseManagement();
app.UseGrpcListener();
app.UseIngress();

await app.RunAsync();

return 0;
