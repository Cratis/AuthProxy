// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.Links.for_LinkSubjectExchanger.given;

namespace Cratis.AuthProxy.Links.for_LinkSubjectExchanger;

public class when_the_exchange_url_is_not_configured : a_link_subject_exchanger
{
    LinkExchangeResult _result;

    protected override C.AuthProxy CreateConfig() => new() { Link = null };

    async Task Because() => _result = await _exchanger.Exchange(_principal, _properties);

    [Fact] void should_fail() => _result.ShouldEqual(LinkExchangeResult.Failed);
    [Fact] void should_not_post_anything() => _handler.LastRequest.ShouldBeNull();
}
