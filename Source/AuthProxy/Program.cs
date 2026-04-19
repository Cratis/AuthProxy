// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy;
using Cratis.AuthProxy.Authentication;
using Cratis.AuthProxy.Identity;
using Cratis.AuthProxy.Invites;
using Cratis.AuthProxy.ReverseProxy;
using Cratis.AuthProxy.Tenancy;

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

public partial class Program;

