// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Net;
using Cratis.AuthProxy.Links.for_LinkSubjectExchanger.given;

namespace Cratis.AuthProxy.Links.for_LinkSubjectExchanger;

public class when_the_endpoint_returns_an_error : a_link_subject_exchanger
{
    LinkExchangeResult _result;

    protected override HttpStatusCode ExchangeStatusCode => HttpStatusCode.InternalServerError;

    async Task Because() => _result = await _exchanger.Exchange(_principal, _properties);

    [Fact] void should_fail() => _result.ShouldEqual(LinkExchangeResult.Failed);
}
