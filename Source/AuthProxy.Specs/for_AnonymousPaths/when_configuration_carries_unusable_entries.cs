// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.for_AnonymousPaths;

/// <summary>
/// Entries that cannot express a path prefix must be discarded rather than matched.
/// <para>
/// The empty entry is the one that matters: <c>PathString.StartsWithSegments(string.Empty)</c> is true
/// for every request, so a stray blank value — an env var set but never given a value, a trailing index
/// in a configuration array — would otherwise turn the entire service anonymous, silently and globally.
/// That is the worst possible failure for this feature, so it is pinned here rather than left to review.
/// The bare <c>/</c> is the same failure spelled differently.
/// </para>
/// <para>
/// The route-template characters are the second class. A prefix is interpolated into an ASP.NET route
/// template, so <c>/a{x}</c> would become a route <em>parameter</em> and make the router match
/// <c>/anything/…</c> while the middlewares matched only the literal — the two components disagreeing
/// about the same prefix, which is the failure the shared matcher exists to prevent.
/// </para>
/// </summary>
public class when_configuration_carries_unusable_entries : Specification
{
    C.AuthProxy _configuration;
    C.Service _service;

    void Establish()
    {
        _service = new C.Service
        {
            AnonymousPaths =
            [
                string.Empty,
                "   ",
                "/",
                "///",
                "no-leading-slash",
                "/double//segment",
                "/with space",
                "/route{parameter}",
                "/catch/{**all}",
                "/query?token=1",
                "/star*",
                "/percent%20encoded",
                "  /portal/  ",
            ],
        };

        _configuration = new C.AuthProxy
        {
            Services = new Dictionary<string, C.Service> { ["test"] = _service },
        };
    }

    [Fact] void should_keep_only_the_usable_entry() => AnonymousPaths.For(_service).ShouldContainOnly("/portal");
    [Fact] void should_not_match_an_unrelated_path() => AnonymousPaths.Matches("/dashboard", _configuration).ShouldBeFalse();
    [Fact] void should_not_match_the_root_path() => AnonymousPaths.Matches("/", _configuration).ShouldBeFalse();
    [Fact] void should_not_match_an_arbitrary_first_segment() => AnonymousPaths.Matches("/anything", _configuration).ShouldBeFalse();
    [Fact] void should_not_match_the_route_parameter_entry_literally() => AnonymousPaths.Matches("/route{parameter}", _configuration).ShouldBeFalse();
    [Fact] void should_not_match_below_the_catch_all_entry() => AnonymousPaths.Matches("/catch/anything", _configuration).ShouldBeFalse();
    [Fact] void should_match_the_trimmed_entry() => AnonymousPaths.Matches("/portal", _configuration).ShouldBeTrue();
    [Fact] void should_match_below_the_trimmed_entry() => AnonymousPaths.Matches("/portal/report", _configuration).ShouldBeTrue();
    [Fact] void should_not_match_a_path_sharing_only_a_string_prefix() => AnonymousPaths.Matches("/portalx", _configuration).ShouldBeFalse();
}
