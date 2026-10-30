// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.ReverseProxy.for_StickyRoutingConfigurationValidator.given;

/// <summary>
/// A validator and helpers to build a configuration with one backend carrying sticky routing.
/// </summary>
public class a_validator : Specification
{
    protected ValidateOptionsResult _result;

    protected static C.StickyRouting Sticky(string replicaHost = "core-headless.svc", TimeSpan? refresh = null, bool enabled = true) =>
        new() { Enabled = enabled, ReplicaHost = replicaHost, RefreshInterval = refresh ?? C.StickyRouting.DefaultRefreshInterval };

    protected static C.AuthProxy Backend(C.StickyRouting sticky, string name = "core", string baseUrl = "http://core:8080/") =>
        new() { Services = new Dictionary<string, C.Service>() { [name] = new() { Backend = new() { BaseUrl = baseUrl, StickyRouting = sticky } } } };

    protected static ValidateOptionsResult Validate(C.AuthProxy options) => new StickyRoutingConfigurationValidator().Validate(null, options);
}
