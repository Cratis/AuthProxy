// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.Extensions.Options;

namespace Cratis.AuthProxy.Security.for_BearerRoutes;

/// <summary>
/// A bearer route AuthProxy could not enforce as written stops the host from starting, rather than silently leaving
/// its path on the browser-session model: a route overlapping an anonymous path, repeating another route's prefix,
/// or naming no issuer or audience is named in the startup failure.
/// </summary>
public class when_a_bearer_route_is_misconfigured : IDisposable
{
    readonly MisconfiguredHarness _harness = new();
    readonly Exception? _startup;

    public when_a_bearer_route_is_misconfigured() =>
        _startup = Record.Exception(() => _harness.CreateClient().Dispose());

    [Fact] public void should_refuse_to_start() => Assert.IsType<OptionsValidationException>(_startup);
    [Fact] public void should_name_the_overlap_with_an_anonymous_path() => Assert.Contains("overlaps the anonymous path", _startup!.Message, StringComparison.Ordinal);
    [Fact] public void should_name_the_repeated_prefix() => Assert.Contains("is already a bearer route", _startup!.Message, StringComparison.Ordinal);
    [Fact] public void should_name_the_missing_issuer() => Assert.Contains($"{nameof(C.BearerRoute.Issuers)} is empty", _startup!.Message, StringComparison.Ordinal);
    [Fact] public void should_name_the_missing_audience() => Assert.Contains($"{nameof(C.BearerRoute.Audiences)} is empty", _startup!.Message, StringComparison.Ordinal);

    public void Dispose()
    {
        _harness.Dispose();
        GC.SuppressFinalize(this);
    }

    sealed class MisconfiguredHarness : BearerRouteHarness
    {
        protected override void AddSettings(IDictionary<string, string?> settings)
        {
            settings[$"{C.AuthProxy.SectionKey}:Services:app:AnonymousPaths:0"] = $"{RoutePrefix}/public";
            settings[$"{C.AuthProxy.SectionKey}:Services:app:BearerRoutes:3:PathPrefix"] = ForwardingRoutePrefix;
        }
    }
}
