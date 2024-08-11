use dep::std;
use dep::verify_signers::verify_signers;

fn main(
    signers: [dep::verify_signers::PubKey; 10],
    signatures: [dep::verify_signers::Signature; 10],
    txn_hash: pub dep::verify_signers::Hash,
    owners_root: Field,
    indices: [Field; 10],
    paths: [[Field; dep::verify_signers::TREE_SIZE]; 10]
)-> pub u64 {
    let num_verified_signatures = verify_signers(signers, signatures, txn_hash, owners_root, indices, paths);

    let num_verified_signatures = 10;
    num_verified_signatures
}