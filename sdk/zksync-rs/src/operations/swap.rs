use num::BigUint;
use zksync_eth_signer::{EthereumSigner, PrivateKeySigner};
use zksync_types::{helpers::{closest_packable_fee_amount, is_fee_amount_packable}, tokens::TxFeeTypes, tx::PackedEthSignature, Address, Nonce, Token, TokenLike, ZkSyncTx, H256, Order, TokenId, AccountId, H160, PubKeyHash};

use crate::{error::ClientError, operations::SyncTransactionHandle, provider::Provider, wallet::Wallet, RpcProvider, WalletCredentials};
use zksync_crypto::{Engine};
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
use zksync_types::tx::TxEthSignature;
use zksync_eth_signer::error::SignerError;

// #[derive(Debug)]
pub struct SwapBuilder<'a, S: EthereumSigner, P: Provider> {
    wallet: &'a Wallet<S, P>,
    recipient: Option<Address>,
    orders: Option<(Order , Order)>,
    order_sigs: Vec<Option<PackedEthSignature>>,
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
            order_sigs: Vec::new(),
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
    pub async fn send(self, order_sigs: (Option<PackedEthSignature>, Option<PackedEthSignature>)) -> Result<SyncTransactionHandle<P>, ClientError> {
        let provider = self.wallet.provider.clone();

        let (tx, eth_signature) = self.tx().await?;
        let mut eth_sigs = Vec::new();
        eth_sigs.push(eth_signature);
        eth_sigs.push(order_sigs.0);
        eth_sigs.push(order_sigs.1);


        let tx_hash = provider.send_swap_tx(tx, Some(eth_sigs)).await?;

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
        self.amounts = Some((orders.0.amount.clone(), orders.1.amount.clone()));
        self.orders = Some(orders);
        self
    }

    /// Sets the transaction recipient.
    pub fn recipient(mut self, recipient: Address) -> Self {
        self.recipient = Some(recipient);
        self
    }

    pub fn amounts(mut self, amounts: (BigUint, BigUint)) -> Self {
        self.amounts = Some(amounts);
        self
    }


    /// Sets the transaction content hash.
    pub async fn gen_order(&self, account_id: u32, eth_sk: H256, nonce: u32, amount: u128, token_id:(u32, u32), price: (u64, u64), zksync_priv: &PrivateKey<Engine>, token_sel: String, token_buy: String) -> (Order, Option<PackedEthSignature>) {
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
            zksync_priv
        ).expect("order creation failed");
        let verf = order.verify_signature();
        info!("verf:{:?}",verf);
        // let message = order.get_ethereum_sign_message("ETH","DAI", 18);

        let eth_signature = match &self.wallet.signer.eth_signer {
            Some(signer) => {
                let message =
                    order.get_ethereum_sign_message(&token_sel,&token_buy, 18);
                let signature = signer.sign_message(&message.as_bytes()).await.unwrap();

                if let TxEthSignature::EthereumSignature(packed_signature) = signature {
                    Some(packed_signature)
                } else {
                    info!("{:?}",SignerError::MissingEthSigner);
                    None
                }
            }
            _ => None,
        };
        return (order, eth_signature);
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
    let order = swap_build.gen_order(0,  sk, 1, 100_000_000_000_000_000, (0,1), (1000, 10000),
                                     &alice_wallet1.signer.private_key,"ETH".to_string() , "DAI".to_string() ).await;
    info!("order:{:?},sig:{:?}", order.0, order.1);
}

#[tokio::test]
async fn swap_tx_send_test() {
    init_log("info");
    let prv_order1 = "f743a8ac1a163c1db8abad36960a6b685507f0feac3e761fe910aec7a7bd0b68";
    let prv_order2 = "0dae11faa7b5075c426a88888f4d2250aeea58b2f0c68c4c428f28df8d56e129";

    let provider = RpcProvider::new(Network::Localhost);
    let eth_sk_order1 = H256::from_str(prv_order1).unwrap();
    let eth_sk_order2 = H256::from_str(prv_order2).unwrap();

    let mut order1_wallet = make_wallet(provider.clone(), eth_user_account_credentials(prv_order1),Network::Localhost).await.unwrap();
    let mut order2_wallet = make_wallet(provider.clone(), eth_user_account_credentials(prv_order2),Network::Localhost).await.unwrap();
    let mut swap_build  = order1_wallet.start_swap();
    let mut order_build  = order2_wallet.start_swap();

    let mut order1 = swap_build.gen_order(2,  eth_sk_order1, 1, 100_000_000_000_000_000, (0,1), (1000, 10000), &order1_wallet.signer.private_key, "ETH".to_string() , "DAI".to_string()).await;
    let mut order2 = order_build.gen_order(1,  eth_sk_order2, 3, 1_000_000_000_000_000_000, (1,0), ( 10000, 1000), &order2_wallet.signer.private_key, "DAI".to_string(), "ETH".to_string()).await;

    let handle = swap_build.fee_token(TokenId(0)).unwrap().recipient(order1_wallet.address()).nonce(Nonce(1)).orders((order1.0,order2.0)).send((order1.1,order2.1)).await;
    if let Ok(handle) = handle {
        let res = handle
            .commit_timeout(std::time::Duration::from_secs(180))
            .wait_for_commit()
            .await;
        println!("res:{:?}", res);
    } else {
        println!("err:{:?}", handle);
    }
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