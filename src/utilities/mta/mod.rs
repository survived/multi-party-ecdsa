/*
    Multi-party ECDSA

    Copyright 2018 by Kzen Networks

    This file is part of Multi-party ECDSA library
    (https://github.com/KZen-networks/multi-party-ecdsa)

    Multi-party ECDSA is free software: you can redistribute
    it and/or modify it under the terms of the GNU General Public
    License as published by the Free Software Foundation, either
    version 3 of the License, or (at your option) any later version.

    @license GPL-3.0+ <https://github.com/KZen-networks/multi-party-ecdsa/blob/master/LICENSE>
*/

/// MtA is descrbied in https://eprint.iacr.org/2019/114.pdf section 3
use std::fmt::Debug;

use curv::arithmetic::traits::Samplable;
use curv::cryptographic_primitives::proofs::sigma_dlog::DLogProof;
use curv::elliptic::curves::traits::*;
use curv::BigInt;
use derivative::Derivative;
use paillier::traits::EncryptWithChosenRandomness;
use paillier::{Add, Decrypt, Mul};
use paillier::{DecryptionKey, EncryptionKey, Paillier, Randomness, RawCiphertext, RawPlaintext};
use serde::{Deserialize, Serialize};

use crate::protocols::multi_party_ecdsa::gg_2018::party_i::PartyPrivate;
use crate::Error::{self, InvalidKey};
use zeroize::Zeroize;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MessageA {
    pub c: BigInt, // paillier encryption
}

#[derive(Derivative, Serialize, Deserialize)]
#[derivative(Clone(bound = "P: Clone, P::Scalar: Clone"))]
#[derivative(Debug(bound = "P: Debug, P::Scalar: Debug"))]
#[serde(bound(serialize = "P: Serialize, P::Scalar: Serialize"))]
#[serde(bound(deserialize = "P: Deserialize<'de>, P::Scalar: Deserialize<'de>"))]
pub struct MessageB<P: ECPoint> {
    pub c: BigInt, // paillier encryption
    pub b_proof: DLogProof<P>,
    pub beta_tag_proof: DLogProof<P>,
}

impl MessageA {
    pub fn a<S: ECScalar>(a: &S, alice_ek: &EncryptionKey) -> (Self, BigInt) {
        let randomness = BigInt::sample_below(&alice_ek.n);
        let c_a = Paillier::encrypt_with_chosen_randomness(
            alice_ek,
            RawPlaintext::from(a.to_big_int()),
            &Randomness::from(randomness.clone()),
        );
        (
            Self {
                c: c_a.0.clone().into_owned(),
            },
            randomness,
        )
    }

    pub fn a_with_predefined_randomness<S: ECScalar>(
        a: &S,
        alice_ek: &EncryptionKey,
        randomness: &BigInt,
    ) -> Self {
        let c_a = Paillier::encrypt_with_chosen_randomness(
            alice_ek,
            RawPlaintext::from(a.to_big_int()),
            &Randomness::from(randomness.clone()),
        );

        Self {
            c: c_a.0.clone().into_owned(),
        }
    }
}

impl<P> MessageB<P>
where
    P: ECPoint + Clone + Send + Sync,
    P::Scalar: Zeroize + Clone + PartialEq + Sync,
{
    pub fn b(
        b: &P::Scalar,
        bob_ek: &EncryptionKey,
        c_a: MessageA,
    ) -> (Self, P::Scalar, BigInt, BigInt) {
        let beta_tag_fe: P::Scalar = ECScalar::new_random();
        let beta_tag = beta_tag_fe.to_big_int();
        let randomness = BigInt::sample_below(&bob_ek.n);
        let c_beta_tag = Paillier::encrypt_with_chosen_randomness(
            bob_ek,
            RawPlaintext::from(beta_tag.clone()),
            &Randomness::from(randomness.clone()),
        );

        let b_bn = b.to_big_int();
        let b_c_a = Paillier::mul(bob_ek, RawCiphertext::from(c_a.c), RawPlaintext::from(b_bn));
        let c_b = Paillier::add(bob_ek, b_c_a, c_beta_tag);
        let beta = <P::Scalar as ECScalar>::zero().sub(&beta_tag_fe.get_element());
        let dlog_proof_b = DLogProof::prove(b);
        let dlog_proof_beta_tag = DLogProof::prove(&beta_tag_fe);

        (
            Self {
                c: c_b.0.clone().into_owned(),
                b_proof: dlog_proof_b,
                beta_tag_proof: dlog_proof_beta_tag,
            },
            beta,
            randomness,
            beta_tag,
        )
    }

    pub fn b_with_predefined_randomness(
        b: &P::Scalar,
        alice_ek: &EncryptionKey,
        c_a: MessageA,
        randomness: &BigInt,
        beta_tag: &BigInt,
    ) -> (Self, P::Scalar) {
        let beta_tag_fe: P::Scalar = ECScalar::from(beta_tag);
        let c_beta_tag = Paillier::encrypt_with_chosen_randomness(
            alice_ek,
            RawPlaintext::from(beta_tag),
            &Randomness::from(randomness.clone()),
        );

        let b_bn = b.to_big_int();
        let b_c_a = Paillier::mul(
            alice_ek,
            RawCiphertext::from(c_a.c),
            RawPlaintext::from(b_bn),
        );
        let c_b = Paillier::add(alice_ek, b_c_a, c_beta_tag);
        let beta = <P::Scalar as ECScalar>::zero().sub(&beta_tag_fe.get_element());
        let dlog_proof_b = DLogProof::prove(b);
        let dlog_proof_beta_tag = DLogProof::prove(&beta_tag_fe);

        (
            Self {
                c: c_b.0.clone().into_owned(),
                b_proof: dlog_proof_b,
                beta_tag_proof: dlog_proof_beta_tag,
            },
            beta,
        )
    }

    pub fn verify_proofs_get_alpha(
        &self,
        dk: &DecryptionKey,
        a: &P::Scalar,
    ) -> Result<(P::Scalar, BigInt), Error> {
        let alice_share = Paillier::decrypt(dk, &RawCiphertext::from(self.c.clone()));
        let g: P = ECPoint::generator();
        let alpha: P::Scalar = ECScalar::from(&alice_share.0);
        let g_alpha = g * alpha.clone();
        let ba_btag = self.b_proof.pk.clone() * a.clone() + self.beta_tag_proof.pk.clone();
        if DLogProof::verify(&self.b_proof).is_ok()
            && DLogProof::verify(&self.beta_tag_proof).is_ok()
            // we prove the correctness of the ciphertext using this check and the proof of knowledge of dlog of beta_tag
            && ba_btag== g_alpha
        {
            Ok((alpha, alice_share.0.into_owned()))
        } else {
            Err(InvalidKey)
        }
    }

    //  another version, supporting PartyPrivate therefore binding mta to gg18.
    //  with the regular version mta can be used in general
    pub fn verify_proofs_get_alpha_gg18(
        &self,
        private: &PartyPrivate<P>,
        a: &P::Scalar,
    ) -> Result<P::Scalar, Error> {
        let alice_share = private.decrypt(self.c.clone());
        let g: P = ECPoint::generator();
        let alpha: P::Scalar = ECScalar::from(&alice_share.0);
        let g_alpha = g * alpha.clone();
        let ba_btag = self.b_proof.pk.clone() * a.clone() + self.beta_tag_proof.pk.clone();

        if DLogProof::verify(&self.b_proof).is_ok()
            && DLogProof::verify(&self.beta_tag_proof).is_ok()
            && ba_btag == g_alpha
        {
            Ok(alpha)
        } else {
            Err(InvalidKey)
        }
    }

    pub fn verify_b_against_public(public_gb: &P, mta_gb: &P) -> bool {
        public_gb == mta_gb
    }
}

#[cfg(test)]
mod test;
