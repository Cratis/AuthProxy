// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy;
using Cratis.AuthProxy.Authentication;
using Cratis.AuthProxy.Authorization;
using Cratis.AuthProxy.Identity;
using Cratis.AuthProxy.Invites;
using Cratis.AuthProxy.Links;
using Cratis.AuthProxy.Management;
using Cratis.AuthProxy.ReverseProxy;
using Cratis.AuthProxy.SignIns;
using Cratis.AuthProxy.Tenancy;

var builder = WebApplication.CreateBuilder(args);

builder.Configuration.AddEnvironmentVariables();

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

var app = builder.Build();

// First, so a request on the private management listener is answered before authentication, tenancy or the
// reverse proxy can see it — and so a request for a management path on the public listener is refused
// before anything else can serve it.
app.UseManagement();
app.UseIngress();

await app.RunAsync();

