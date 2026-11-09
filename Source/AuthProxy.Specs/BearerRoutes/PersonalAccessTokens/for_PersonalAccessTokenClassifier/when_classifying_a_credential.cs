// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.BearerRoutes.PersonalAccessTokens.for_PersonalAccessTokenClassifier;

public class when_classifying_a_credential : Specification
{
    [Theory]
    [InlineData("direct")]
    [InlineData("studio")]
    [InlineData("stage-my-app")]
    public void should_accept_a_canonical_token_and_name_its_resource(string resourceKey)
    {
        var shape = PersonalAccessTokenClassifier.Classify(TestPersonalAccessTokens.Create(resourceKey));
        shape.Kind.ShouldEqual(PersonalAccessTokenKind.Canonical);
        shape.ResourceKey.ShouldEqual(resourceKey);
    }

    [Fact]
    public void should_treat_a_bad_checksum_as_malformed() =>
        PersonalAccessTokenClassifier.Classify(TestPersonalAccessTokens.CreateWithBadChecksum("direct")).Kind.ShouldEqual(PersonalAccessTokenKind.Malformed);

    [Theory]
    [InlineData("direct_PAT_v1_aaaa")]
    [InlineData("direct_pat_v2_aaaa")]
    [InlineData("unknown_pat_v1_aaaa")]
    [InlineData("stage-_pat_v1_aaaa")]
    [InlineData("direct_pat_")]
    public void should_treat_a_value_in_the_namespace_that_is_not_canonical_as_malformed(string value) =>
        PersonalAccessTokenClassifier.Classify(value).Kind.ShouldEqual(PersonalAccessTokenKind.Malformed);

    [Fact]
    public void should_treat_an_uppercase_hex_secret_as_malformed()
    {
        var token = TestPersonalAccessTokens.Create("direct", 'a').Replace("direct_pat_v1_a", "direct_pat_v1_A", StringComparison.Ordinal);
        PersonalAccessTokenClassifier.Classify(token).Kind.ShouldEqual(PersonalAccessTokenKind.Malformed);
    }

    [Theory]
    [InlineData("eyJhbGciOiJSUzI1NiJ9.e30.c2ln")]
    [InlineData("opaque-token")]
    [InlineData("")]
    [InlineData("_pat_x")]
    public void should_leave_everything_else_to_the_other_branch(string value) =>
        PersonalAccessTokenClassifier.Classify(value).Kind.ShouldEqual(PersonalAccessTokenKind.NotPersonalAccessToken);

    [Theory]
    [InlineData("direct", true)]
    [InlineData("studio", true)]
    [InlineData("stage-a", true)]
    [InlineData("stage-a-b", true)]
    [InlineData("stage-", false)]
    [InlineData("stage--a", false)]
    [InlineData("stage-a-", false)]
    [InlineData("stage-A", false)]
    [InlineData("Direct", false)]
    [InlineData("", false)]
    [InlineData(null, false)]
    public void should_validate_resource_keys(string? key, bool expected) =>
        PersonalAccessTokenClassifier.IsValidResourceKey(key).ShouldEqual(expected);
}
