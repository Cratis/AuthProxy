// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

var builder = DistributedApplication.CreateBuilder(args);

var testApp = builder.AddProject<Projects.TestApp>("testapp")
    .WithHttpEndpoint(port: 5001);

builder.AddNpmApp("web", "../Web")
    .WithHttpEndpoint(port: 9100, env: "PORT");

builder.AddProject<Projects.AuthProxy>("authproxy")
    .WithHttpEndpoint(port: 8080)
    .WithReference(testApp)
    .WaitFor(testApp);

await builder.Build().RunAsync();
