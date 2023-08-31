// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

import type { WalletWithSuiFeatures, WalletAccount } from '@mysten/wallet-standard';
import { assertUnreachable } from 'dapp-kit/src/utils/assertUnreachable';

export type WalletState = {
	wallets: WalletWithSuiFeatures[];
	currentWallet: WalletWithSuiFeatures | null;
	accounts: readonly WalletAccount[];
	currentAccount: WalletAccount | null;
};

export type WalletAction =
	| {
			type: 'wallet-connected';
			payload: { wallet: WalletWithSuiFeatures; selectedAccount: WalletAccount | null };
	  }
	| { type: 'wallet-disconnected'; payload?: never }
	| { type: 'wallet-properties-changed'; payload: { updatedAccounts: WalletAccount[] } }
	| { type: 'wallets-changed'; payload: WalletWithSuiFeatures[] };

export function walletReducer(
	walletState: WalletState,
	{ type, payload }: WalletAction,
): WalletState {
	switch (type) {
		case 'wallet-connected':
			return {
				...walletState,
				currentWallet: payload.wallet,
				accounts: payload.wallet.accounts,
				currentAccount: payload.selectedAccount,
			};
		case 'wallet-disconnected': {
			return {
				...walletState,
				currentWallet: null,
				accounts: [],
				currentAccount: null,
			};
		}
		case 'wallet-properties-changed': {
			return {
				...walletState,
				accounts: [],
				currentAccount: null,
			};
		}
		case 'wallets-changed': {
			return {
				...walletState,
				wallets: payload,
				// TODO: if the current wallet is un-registered... we should reset our state?
			};
		}
		default:
			assertUnreachable(type);
	}
}