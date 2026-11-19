// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Ingress.for_DeniedPathNormalization;

public class when_the_raw_target_is_ambiguous
{
    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("*")]
    [InlineData("http://public.test/internal")]
    [InlineData("internal")]
    [InlineData("/../internal")]
    [InlineData("/a/../../internal")]
    [InlineData("/%2e%2e/internal")]
    [InlineData("/internal\\child")]
    [InlineData("/internal%5cchild")]
    [InlineData("/internal%5Cchild")]
    [InlineData("/internal%2fchild")]
    [InlineData("/internal%2Fchild")]
    [InlineData("/%2569nternal")]
    [InlineData("/internal%252fchild")]
    [InlineData("/%252e%252e/internal")]
    [InlineData("/internal;parameter")]
    [InlineData("/internal%3bparameter")]
    [InlineData("/internal#fragment")]
    [InlineData("/internal%23fragment")]
    [InlineData("/internal%3fquery")]
    [InlineData("/public%00")]
    [InlineData("/public%0a")]
    [InlineData("/public%7f")]
    [InlineData("/public%20")]
    [InlineData("/public\t")]
    [InlineData("/public%")]
    [InlineData("/public%2")]
    [InlineData("/public%gg")]
    [InlineData("/public%25")]
    [InlineData("/%C0%AFinternal")]
    [InlineData("/%FF")]
    [InlineData("/%E2%82")]
    [InlineData("/%ED%A0%80")]
    [InlineData("/é")]
    public void should_refuse_instead_of_guessing(string? target) =>
        DeniedPathNormalization.TryNormalize(target, out _).ShouldBeFalse();
}
