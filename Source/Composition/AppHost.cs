// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.Aspire;

var builder = DistributedApplication.CreateBuilder(args);

var testApp = builder.AddProject<Projects.TestApp>("testapp")
    .WithHttpEndpoint(port: 5001);

var web = builder.AddNpmApp("web", "../Web")
    .WithHttpEndpoint(port: 9100, env: "PORT");

builder.AddProject<Projects.AuthProxy>("authproxy")
    .WithHttpEndpoint(port: 8080)
    .WithBackend("main", testApp)
    .WithFrontend("main", web)
    .WaitFor(testApp);

await builder.Build().RunAsync();
