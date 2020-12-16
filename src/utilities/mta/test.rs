use crate::utilities::mta::*;
use curv::elliptic::curves::traits::ECScalar;
use curv::test_for_all_curves;
use paillier::traits::KeyGeneration;

test_for_all_curves!(test_mta);
fn test_mta<P>()
where
    P: ECPoint + Clone + Send + Sync,
    P::Scalar: Zeroize + Clone + PartialEq + Sync + std::fmt::Debug,
{
    let alice_input: P::Scalar = ECScalar::new_random();
    let (ek_alice, dk_alice) = Paillier::keypair().keys();
    let bob_input: P::Scalar = ECScalar::new_random();
    let (m_a, _r) = MessageA::a(&alice_input, &ek_alice);
    let (m_b, beta, _, _) = MessageB::<P>::b(&bob_input, &ek_alice, m_a);
    let alpha = m_b
        .verify_proofs_get_alpha(&dk_alice, &alice_input)
        .expect("wrong dlog or m_b");

    let left = alpha.0 + beta;
    let right = alice_input * bob_input;
    assert_eq!(left, right);
}
