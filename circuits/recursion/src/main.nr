use dep::verify_signers::verify_signers;

#[recursive]
fn main(
    verification_key: [Field; 114],
    public_inputs: pub [Field; 3],
    key_hash: Field,
    proof: [Field; 109], // TODO: FIX NUMBER
    signers: [dep::verify_signers::PubKey; 10], 
    signatures: [dep::verify_signers::Signature; 10], 
    txn_hash: pub dep::verify_signers::Hash, 
    owners_root: pub dep::verify_signers::Hash, 
    indices: [Field; 10], 
    paths: [[[u8; 32]; dep::verify_signers::TREE_SIZE]; 10]
) -> pub u64 {
    // verify signers so far are properly verified
    std::verify_proof(
        verification_key.as_slice(),
        proof.as_slice(),
        public_inputs.as_slice(),
        key_hash
    );

    let mut num_verified_signatures = verify_signers(signers, signatures, txn_hash, owners_root, indices, paths);
    num_verified_signatures += public_inputs[2] as u64;
    num_verified_signatures
}