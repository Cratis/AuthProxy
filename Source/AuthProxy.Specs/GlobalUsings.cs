// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

global using System.Security.Claims;
global using System.Text.Json.Nodes;
global using Cratis.AuthProxy.ErrorPages;
global using Cratis.AuthProxy.Identity;
global using Cratis.AuthProxy.Tenancy;
global using Cratis.Specifications;
global using Microsoft.AspNetCore.Http;
global using Microsoft.Extensions.Logging;
global using Microsoft.Extensions.Options;
global using NSubstitute;
global using Xunit;
global using C = Cratis.AuthProxy.Configuration;
