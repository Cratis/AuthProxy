// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace E2E.OAuthGrantReceiver;

sealed record VerifiedGrant(VerifiedBearerResult Bearer, long AuthTime);
