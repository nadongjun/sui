// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

import { graphql } from 'gql.tada';

import './generated/2024-01/tada-env.js';

const getObject = graphql(`
	query getObject($address: SuiAddress!, $version: Int) {
		object(address: $address, version: $version) {
			__typename
			address
			version
			digest
		}
	}
`);

export const SuiQueries = {
	getObject,
};
