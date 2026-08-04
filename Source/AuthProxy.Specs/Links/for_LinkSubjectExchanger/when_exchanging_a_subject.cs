// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.Links.for_LinkSubjectExchanger.given;

namespace Cratis.AuthProxy.Links.for_LinkSubjectExchanger;

public class when_exchanging_a_subject : a_link_subject_exchanger
{
    LinkExchangeResult _result;

    async Task Because() => _result = await _exchanger.Exchange(_principal, _properties);

    [Fact] void should_succeed() => _result.ShouldEqual(LinkExchangeResult.Success);
    [Fact] void should_post_to_the_configured_exchange_url() => _handler.LastRequest!.RequestUri!.ToString().ShouldEqual(ExchangeUrl);
    [Fact] void should_post() => _handler.LastRequest!.Method.ShouldEqual(HttpMethod.Post);
    [Fact] void should_authenticate_with_the_link_token() => _handler.LastRequest!.Headers.Authorization!.Parameter.ShouldEqual(LinkToken);
    [Fact] void should_use_the_bearer_scheme() => _handler.LastRequest!.Headers.Authorization!.Scheme.ShouldEqual("Bearer");
    [Fact] void should_send_the_linked_subject() => _handler.LastRequestBody!.ShouldContain("linked-subject-123");
    [Fact] void should_send_the_identity_provider() => _handler.LastRequestBody!.ShouldContain("https://github.com");
}
