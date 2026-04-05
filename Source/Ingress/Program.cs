// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.Ingress;
using Cratis.Ingress.Authentication;
using Cratis.Ingress.Identity;
using Cratis.Ingress.Invites;
using Cratis.Ingress.ReverseProxy;
using Cratis.Ingress.Tenancy;

var builder = WebApplication.CreateBuilder(args);

builder.Configuration.AddEnvironmentVariables();

builder.AddIngressConfiguration();
builder.AddIngressAuthentication();
builder.AddTenancy();
builder.AddIdentityResolution();
builder.AddInvites();
builder.SetupReverseProxy();

var app = builder.Build();

app.UseIngress();

await app.RunAsync();

