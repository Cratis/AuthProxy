// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Ingress.for_DeniedPathConfigurationValidator;

public class when_validating_prefixes
{
    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("relative")]
    [InlineData("/../internal")]
    [InlineData("/a..b")]
    [InlineData("/a/../internal")]
    [InlineData("/%69nternal")]
    [InlineData("/internal\\child")]
    [InlineData("/internal;parameter")]
    [InlineData("/internal?query")]
    [InlineData("/internal#fragment")]
    [InlineData("/internal\n")]
    [InlineData("/internal child")]
    [InlineData("/é")]
    [InlineData("/internal/*")]
    [InlineData("/internal?")]
    [InlineData("/internal/[id]")]
    [InlineData("/internal/{id}")]
    [InlineData("/internal|other")]
    [InlineData("/internal^other")]
    [InlineData("/internal<other>")]
    [InlineData("/internal/./child")]
    public void should_reject_invalid_entries_with_the_configuration_key(string? prefix)
    {
        var result = new DeniedPathConfigurationValidator().Validate(null, new C.Ingress { DeniedPathPrefixes = [prefix] });
        result.Failed.ShouldBeTrue();
        result.Failures.Single().ShouldContain("Ingress:DeniedPathPrefixes:0");
    }

    [Theory]
    [InlineData("/")]
    [InlineData("/internal")]
    [InlineData("/INTERNAL/")]
    [InlineData("//internal/child")]
    [InlineData("/internal-name_~!$&'()+,=:@/child")]
    public void should_accept_plain_absolute_paths(string prefix) =>
        new DeniedPathConfigurationValidator().Validate(null, new C.Ingress { DeniedPathPrefixes = [prefix] }).Succeeded.ShouldBeTrue();

    [Fact]
    public void should_accept_the_empty_default() =>
        new DeniedPathConfigurationValidator().Validate(null, new C.Ingress()).Succeeded.ShouldBeTrue();
}
