use num::BigUint;
use zksync_eth_signer::{EthereumSigner, PrivateKeySigner};
use zksync_types::{helpers::{closest_packable_fee_amount, is_fee_amount_packable}, tokens::TxFeeTypes, tx::PackedEthSignature, Address, Nonce, Token, TokenLike, ZkSyncTx, H256, Order, TokenId, AccountId, H160, PubKeyHash};

use crate::{error::ClientError, operations::SyncTransactionHandle, provider::Provider, wallet::Wallet, RpcProvider, WalletCredentials};
use zksync_crypto::{/* PrivateKey, */ Engine};
pub use zksync_crypto::franklin_crypto::{
    alt_babyjubjub::fs::FsRepr,
    bellman::{pairing::bn256, PrimeFieldRepr},
};
pub use zksync_crypto::franklin_crypto::{eddsa::PrivateKey, jubjub::JubjubEngine};
use std::str::FromStr;
use zksync_types::network::Network;
use parity_crypto::publickey::KeyPair;
use log::info;
use std::{convert::TryInto, ops::Sub};

use num::FromPrimitive;
use zksync_crypto::ff::PrimeField;

// #[derive(Debug)]
pub struct SwapBuilder<'a, S: EthereumSigner, P: Provider> {
    wallet: &'a Wallet<S, P>,
    recipient: Option<Address>,
    orders: Option<(Order , Order)>,
    amounts:  Option<(BigUint , BigUint)>,
    fee_token: Option<Token>,
    fee: Option<BigUint>,
    nonce: Option<Nonce>,
}

impl<'a, S, P> SwapBuilder<'a, S, P>
    where
        S: EthereumSigner,
        P: Provider + Clone,
{
    /// Initializes a mint nft transaction building process.
    pub fn new(wallet: &'a Wallet<S, P>) -> Self {
        Self {
            wallet,
            recipient: None,
            orders: None,
            amounts: None,
            fee_token: None,
            fee: None,
            nonce: None,
        }
    }

    /// Directly returns the signed mint nft transaction for the subsequent usage.
    pub async fn tx(self) -> Result<(ZkSyncTx, Option<PackedEthSignature>), ClientError> {
        let recipient = self
            .recipient
            .ok_or_else(|| ClientError::MissingRequiredField("recipient".into()))?;
        let fee_token = self
            .fee_token
            .ok_or_else(|| ClientError::MissingRequiredField("fee_token".into()))?;

        let fee = match self.fee {
            Some(fee) => fee,
            None => {
                let fee = self
                    .wallet
                    .provider
                    .get_tx_fee(TxFeeTypes::Swap, recipient, fee_token.id)
                    .await?;
                fee.total_fee
            }
        };

        let nonce = match self.nonce {
            Some(nonce) => nonce,
            None => {
                let account_info = self
                    .wallet
                    .provider
                    .account_info(self.wallet.address())
                    .await?;
                account_info.committed.nonce
            }
        };

        self.wallet
            .signer
            .sign_swap(self.orders.unwrap(), self.amounts.unwrap(), fee_token, fee, nonce)
            .await
            .map(|(tx, signature)| (ZkSyncTx::Swap(Box::new(tx)), signature))
            .map_err(ClientError::SigningError)
    }

    /// Sends the transaction, returning the handle for its awaiting.
    pub async fn send(self) -> Result<SyncTransactionHandle<P>, ClientError> {
        let provider = self.wallet.provider.clone();

        let (tx, eth_signature) = self.tx().await?;
        let tx_hash = provider.send_tx(tx, eth_signature).await?;

        Ok(SyncTransactionHandle::new(tx_hash, provider))
    }

    /// Sets the transaction fee token. Returns an error if token is not supported by zkSync.
    pub fn fee_token(mut self, token: impl Into<TokenLike>) -> Result<Self, ClientError> {
        let token_like = token.into();
        let token = self
            .wallet
            .tokens
            .resolve(token_like)
            .ok_or(ClientError::UnknownToken)?;

        self.fee_token = Some(token);

        Ok(self)
    }

    /// Set the fee amount. If the provided fee is not packable,
    /// rounds it to the closest packable fee amount.
    ///
    /// For more details, see [utils](../utils/index.html) functions.
    pub fn fee(mut self, fee: impl Into<BigUint>) -> Self {
        let fee = closest_packable_fee_amount(&fee.into());
        self.fee = Some(fee);

        self
    }

    /// Set the fee amount. If the provided fee is not packable,
    /// returns an error.
    ///
    /// For more details, see [utils](../utils/index.html) functions.
    pub fn fee_exact(mut self, fee: impl Into<BigUint>) -> Result<Self, ClientError> {
        let fee = fee.into();
        if !is_fee_amount_packable(&fee) {
            return Err(ClientError::NotPackableValue);
        }
        self.fee = Some(fee);

        Ok(self)
    }




    /// Sets the transaction nonce.
    pub fn nonce(mut self, nonce: Nonce) -> Self {
        self.nonce = Some(nonce);
        self
    }

    /// Sets the transaction content hash.
    pub fn orders(mut self, orders: (Order, Order)) -> Self {
        self.orders = Some(orders);
        self
    }



    /// Sets the transaction content hash.
    pub fn gen_order(mut self, account_id: u32, eth_sk: H256, nonce: u32, amount: u128, token_id:(u32,u32), price: (u64,u64)) -> Order {
        let address = PackedEthSignature::address_from_private_key(&eth_sk)
            .expect("Can't get address from the ETH secret key");

        // let prv_key = self.priv_key_from_raw(eth_sk.as_bytes());
        let order = Order::new_signed(
            AccountId(account_id),
            address,
            Nonce(nonce),
            TokenId(token_id.0),
            TokenId(token_id.1),
            (
                BigUint::from(price.0),
                BigUint::from(price.1),
            ),
            BigUint::from(amount),
            Default::default(),
            &self.wallet.signer.private_key,
        ).expect("order creation failed");
        let verf = order.verify_signature();
        println!("verf:{:?}",verf);
        return order;
    }
}

async fn make_wallet(
    provider: RpcProvider,
    (eth_address, eth_private_key): (H160, H256), network: Network
) -> Result<Wallet<PrivateKeySigner, RpcProvider>, ClientError> {
    let eth_signer = PrivateKeySigner::new(eth_private_key);
    let credentials =
        WalletCredentials::from_eth_signer(eth_address, eth_signer, network).await?;
    Wallet::new(provider, credentials).await
}

fn eth_user_account_credentials(private_key: &str) -> (H160, H256) {
    let eth_private_key: H256 = private_key.parse().unwrap();
    let pair = KeyPair::from_secret((eth_private_key).into()).unwrap();
    info!("pub:{:?}", pair.public());
    let address_from_pk = PackedEthSignature::address_from_private_key(&eth_private_key).unwrap();
    info!{"user address:{:?}", address_from_pk};
    (address_from_pk, eth_private_key)
}

pub type Fs = <Engine as JubjubEngine>::Fs;
pub fn read_signing_key(private_key: &[u8]) -> anyhow::Result<PrivateKey<Engine>> {
    let mut fs_repr = FsRepr::default();
    fs_repr.read_be(private_key)?;
    Ok(PrivateKey::<Engine>(
        Fs::from_repr(fs_repr).expect("couldn't read private key from repr"),
    ))
}

#[tokio::test]
async fn order_verify_test() {
    init_log("info");
    // let prv=  "0092788f3890ed50dcab7f72fb574a0a9d30b1bc778ba076c609c311a8555352";
    let prv = "f743a8ac1a163c1db8abad36960a6b685507f0feac3e761fe910aec7a7bd0b68";
    let provider = RpcProvider::new(Network::Localhost);

    let mut alice_wallet1 = make_wallet(provider.clone(), eth_user_account_credentials(prv),Network::Localhost).await.unwrap();

    let sk = H256::from_str(prv).unwrap();
    // let sender_sk = hex::decode(prv)
    //     .expect("Failed to decode forced_exit_sender sk");
    // let sender_sk = read_signing_key(&sender_sk).expect("Failed to read forced exit sender sk");
    let pubkey_hash = PubKeyHash::from_privkey(&alice_wallet1.signer.private_key);
    info!("pubkey_hash:{:?}", pubkey_hash);
    let swap_build  = SwapBuilder::new(&alice_wallet1);
    swap_build.gen_order(0,  sk, 1, 100_000_000_000_000_000, (0,1), (1000, 10000));
}

pub fn init_log(log_level: &str){
    use std::io::Write;
    use chrono::Local;
    let env = env_logger::Env::default().filter_or(env_logger::DEFAULT_FILTER_ENV,log_level);
    env_logger::Builder::from_env(env).format(|buf,record|{
        writeln!(
            buf,
            "{} {} [{}:{}] {} {}",
            Local::now().format("%Y-%m-%d %H:%M:%S"),
            record.level(),
            record.module_path().unwrap_or("<unnamed>"),
            record.line().unwrap_or(0),
            record.target(),
            &record.args()
        )
    }).init();
}