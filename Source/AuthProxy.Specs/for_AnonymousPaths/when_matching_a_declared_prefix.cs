// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.for_AnonymousPaths;

/// <summary>
/// A declared prefix must match on segment boundaries, case-insensitively, and nowhere else.
/// <para>
/// Case-insensitivity is not an accident: ASP.NET route templates match literal segments
/// case-insensitively, so the route table would serve <c>/PORTAL</c> anonymously whatever the middlewares
/// decided. The two have to agree, and this pins which way.
/// </para>
/// </summary>
public class when_matching_a_declared_prefix : Specification
{
    C.AuthProxy _configuration;

    void Establish() => _configuration = new C.AuthProxy
    {
        Services = new Dictionary<string, C.Service>
        {
            ["test"] = new() { AnonymousPaths = ["/portal", "/api/reports/public"] },
        },
    };

    [Fact] void should_match_the_prefix_itself() => AnonymousPaths.Matches("/portal", _configuration).ShouldBeTrue();
    [Fact] void should_match_a_child_segment() => AnonymousPaths.Matches("/portal/token", _configuration).ShouldBeTrue();
    [Fact] void should_match_a_deeply_nested_child() => AnonymousPaths.Matches("/portal/a/b/c", _configuration).ShouldBeTrue();
    [Fact] void should_match_the_prefix_with_a_trailing_slash() => AnonymousPaths.Matches("/portal/", _configuration).ShouldBeTrue();
    [Fact] void should_match_regardless_of_casing() => AnonymousPaths.Matches("/PORTAL/Token", _configuration).ShouldBeTrue();
    [Fact] void should_match_a_declared_leaf_below_an_undeclared_parent() => AnonymousPaths.Matches("/api/reports/public", _configuration).ShouldBeTrue();

    [Fact] void should_not_match_a_longer_first_segment() => AnonymousPaths.Matches("/portalx", _configuration).ShouldBeFalse();
    [Fact] void should_not_match_a_longer_first_segment_with_children() => AnonymousPaths.Matches("/portalx/token", _configuration).ShouldBeFalse();
    [Fact] void should_not_match_the_undeclared_parent_of_a_declared_leaf() => AnonymousPaths.Matches("/api/reports", _configuration).ShouldBeFalse();
    [Fact] void should_not_match_a_sibling_of_a_declared_leaf() => AnonymousPaths.Matches("/api/reports/private", _configuration).ShouldBeFalse();
    [Fact] void should_not_match_a_prefix_appearing_below_the_root() => AnonymousPaths.Matches("/app/portal", _configuration).ShouldBeFalse();
    [Fact] void should_not_match_the_root_path() => AnonymousPaths.Matches("/", _configuration).ShouldBeFalse();
    [Fact] void should_not_match_an_empty_path() => AnonymousPaths.Matches(PathString.Empty, _configuration).ShouldBeFalse();
}
