// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.for_AnonymousPathPolicy;

/// <summary>
/// AuthProxy answers some paths itself, and a declared prefix cannot take them away from it.
/// <para>
/// An anonymous route is emitted at order 0, ahead of every service-selected route, and the three
/// middlewares stop applying their checks below a declared prefix. So pointing one at AuthProxy's own
/// namespace does not make an endpoint public — those endpoints already admit anonymous callers where they
/// are meant to. It <em>removes</em> the endpoint from AuthProxy: a declared <c>/.cratis</c> hands the
/// logout, token, tenant-selection and login endpoints to a backend, and a declared <c>/invite</c> or
/// <c>/register</c> puts those flow middlewares behind a proxied route. Both are configuration mistakes
/// with no legitimate spelling, so they are refused outright.
/// </para>
/// </summary>
public class when_an_entry_targets_a_path_the_proxy_owns : Specification
{
    static AnonymousPathRejection Evaluate(string candidate) => AnonymousPathPolicy.Evaluate(candidate, out _);

    [Fact] void should_refuse_the_proxy_namespace() => Evaluate("/.cratis").ShouldEqual(AnonymousPathRejection.ProxyOwnedPath);
    [Fact] void should_refuse_the_token_endpoint() => Evaluate("/.cratis/token").ShouldEqual(AnonymousPathRejection.ProxyOwnedPath);
    [Fact] void should_refuse_the_logout_endpoint() => Evaluate("/.cratis/logout").ShouldEqual(AnonymousPathRejection.ProxyOwnedPath);
    [Fact] void should_refuse_the_tenant_selection_endpoint() => Evaluate("/.cratis/select-tenant").ShouldEqual(AnonymousPathRejection.ProxyOwnedPath);
    [Fact] void should_refuse_an_unclaimed_path_in_the_proxy_namespace() => Evaluate("/.cratis/anything").ShouldEqual(AnonymousPathRejection.ProxyOwnedPath);
    [Fact] void should_refuse_the_proxy_namespace_regardless_of_casing() => Evaluate("/.CRATIS/Token").ShouldEqual(AnonymousPathRejection.ProxyOwnedPath);
    [Fact] void should_refuse_the_pages_prefix() => Evaluate("/_pages").ShouldEqual(AnonymousPathRejection.ProxyOwnedPath);
    [Fact] void should_refuse_below_the_pages_prefix() => Evaluate("/_pages/error").ShouldEqual(AnonymousPathRejection.ProxyOwnedPath);
    [Fact] void should_refuse_the_invite_prefix() => Evaluate("/invite").ShouldEqual(AnonymousPathRejection.ProxyOwnedPath);
    [Fact] void should_refuse_below_the_invite_prefix() => Evaluate("/invite/token").ShouldEqual(AnonymousPathRejection.ProxyOwnedPath);
    [Fact] void should_refuse_the_registration_path() => Evaluate("/register").ShouldEqual(AnonymousPathRejection.ProxyOwnedPath);
    [Fact] void should_refuse_a_provider_callback() => Evaluate("/signin-microsoft").ShouldEqual(AnonymousPathRejection.ProxyOwnedPath);

    [Fact] void should_keep_a_path_that_only_shares_a_string_prefix_with_the_proxy_namespace() =>
        Evaluate("/.cratisfiles").ShouldEqual(AnonymousPathRejection.None);

    [Fact] void should_keep_a_path_that_only_shares_a_string_prefix_with_the_invite_prefix() =>
        Evaluate("/invites").ShouldEqual(AnonymousPathRejection.None);

    [Fact] void should_keep_a_path_that_merely_contains_a_reserved_name_below_the_root() =>
        Evaluate("/app/invite").ShouldEqual(AnonymousPathRejection.None);
}
