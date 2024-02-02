// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

import { graphql } from 'gql.tada';

import { GraphQLClient } from '../src/index.js';
import { SuiQueries } from '../src/schemas/2024-01/index.js';

const client = new GraphQLClient({
	url: 'http://localhost:8080/graphql',
	queries: SuiQueries,
});

export const object1 = client.execute('getObject', {
	variables: {
		address: '0x123',
	},
});

export const object2 = client.query({
	query: graphql(`
		query getObject($address: SuiAddress!, $version: Int) {
			object(address: $address, version: $version) {
				__typename
				address
				version
				digest
			}
		}
	`),
	variables: {
		address: '0x987',
	},
});
