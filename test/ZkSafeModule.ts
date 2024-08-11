import hre, { ethers, network, deployments } from 'hardhat';
import { expect } from "chai";
import { ZkSafeModule } from "../typechain-types";

import circuit from '../circuits/zkSafe/target/zkSafe.json';

import { BarretenbergBackend } from '@noir-lang/backend_barretenberg';
import { Noir } from '@noir-lang/noir_js';
import { EthersAdapter, SafeFactory, SafeAccountConfig } from '@safe-global/protocol-kit';
import Safe from '@safe-global/protocol-kit';
import { SafeTransactionData } from '@safe-global/safe-core-sdk-types';

import MTBridge from "./depositLib/mt-bridge";
const MerkleTreeOwners = MTBridge;
import {verifyMerkleProof, getLeafValue} from "./depositLib/mt-bridge-utils";

import { CompiledCircuit } from '@noir-lang/types';
import { ProofData } from '@noir-lang/types';

import { join, resolve } from 'path';
import { compile, createFileManager } from '@noir-lang/noir_wasm';
const { buildPoseidon } = require("circomlibjs");

type FullNoir = {
    circuit: CompiledCircuit,
    backend: BarretenbergBackend,
    noir: Noir
  }

  
// Helper function to get compiled Noir program
async function getCircuit(name: string) {
    const basePath = resolve(join('./circuits', name));
    const fm = createFileManager(basePath);
    const compiled = await compile(fm, basePath);
    if (!('program' in compiled)) {
      throw new Error('Compilation failed');
    }
    return compiled.program;
  }

async function fullNoirFromCircuit(circuitName: string): Promise<FullNoir> {
    const circuit: CompiledCircuit = await getCircuit(circuitName);
    const backend: BarretenbergBackend = new BarretenbergBackend(circuit, { threads: 12 });
    const noir: Noir = new Noir(circuit, backend);
    return { circuit, backend, noir };
  }

async function getOwnerAdapters(): Promise<EthersAdapter[]> {
    return (await ethers.getSigners()).slice(0, 3).map((signer) => new EthersAdapter({ ethers, signerOrProvider: signer }));
}

/// Extract x and y coordinates from a serialized ECDSA public key.
function extractCoordinates(serializedPubKey: string): { x: number[], y: number[] } {
    // Ensure the key starts with '0x04' which is typical for an uncompressed key.
    if (!serializedPubKey.startsWith('0x04')) {
        throw new Error('The public key does not appear to be in uncompressed format.');
    }

    // The next 64 characters after the '0x04' are the x-coordinate.
    let xHex = serializedPubKey.slice(4, 68);

    // The following 64 characters are the y-coordinate.
    let yHex = serializedPubKey.slice(68, 132);

    // Convert the hex string to a byte array.
    let xBytes = Array.from(Buffer.from(xHex, 'hex'));
    let yBytes = Array.from(Buffer.from(yHex, 'hex'));
    return { x: xBytes, y: yBytes };
}

function extractRSFromSignature(signatureHex: string): number[] {
    if (signatureHex.length !== 132 || !signatureHex.startsWith('0x')) {
        throw new Error('Signature should be a 130-character hex string starting with 0x.');
    }
    return Array.from(Buffer.from(signatureHex.slice(2, 130), 'hex'));
}

function addressToArray(address: string): number[] {
    if (address.length !== 42 || !address.startsWith('0x')) {
        throw new Error('Address should be a 40-character hex string starting with 0x.');
    }
    return Array.from(ethers.getBytes(address));
}

function padArray(arr: any[], length: number, fill: any = 0) {
    return arr.concat(Array(length - arr.length).fill(fill));
}

describe("ZkSafeModule", function () {
    let ownerAdapters: EthersAdapter[];
    let zkSafeModule: ZkSafeModule;
    let safe: Safe;
    let verifierContract: any;

    // New Noir Way
    let noir: Noir;
    let correctProof: Uint8Array;

    before(async function () {
        ownerAdapters = await getOwnerAdapters();
        // Deploy Safe
        let owners = await Promise.all(ownerAdapters.map((oa) => (oa.getSigner()?.getAddress() as string)));
        console.log("owners", owners);

        await deployments.fixture();

        const deployedSafe = await deployments.get("GnosisSafeL2");
        const deployedSafeFactory = await deployments.get("GnosisSafeProxyFactory");
        const deployedMultiSend = await deployments.get("MultiSend");
        const deployedMultiSendCallOnly = await deployments.get("MultiSendCallOnly");
        const deployedCompatibilityFallbackHandler = await deployments.get("CompatibilityFallbackHandler");
        const deployedSignMessageLib = await deployments.get("SignMessageLib");
        const deployedCreateCall = await deployments.get("CreateCall");
//        const deployedSimulateTxAccessor = await deployments.get("SimulateTxAccessor");
        const chainId: number = await ownerAdapters[0].getChainId();
        const chainIdStr = chainId.toString();
        console.log("chainId: ", chainIdStr);
        const contractNetworks = {
            [chainIdStr]: {
                    safeSingletonAddress: deployedSafe.address,
                    safeProxyFactoryAddress: deployedSafeFactory.address,
                    multiSendAddress: deployedMultiSend.address,
                    multiSendCallOnlyAddress: deployedMultiSendCallOnly.address,
                    fallbackHandlerAddress: deployedCompatibilityFallbackHandler.address,
                    signMessageLibAddress: deployedSignMessageLib.address,
                    createCallAddress: deployedCreateCall.address,
                    simulateTxAccessorAddress: ethers.ZeroAddress,
            }
        };
        const safeFactory = await SafeFactory.create({ ethAdapter: ownerAdapters[0], contractNetworks });

        // Could create multisig with nonexisting owners ( like 0xFFF) to be only a zkMultisig
        const safeAccountConfig: SafeAccountConfig =  {
            owners: owners,
            threshold: 2,
        };

        const verifierContractFactory = await ethers.getContractFactory("UltraVerifier");
        verifierContract = await verifierContractFactory.deploy();
        verifierContract.waitForDeployment();
        console.log("verifierContract", await verifierContract.getAddress());

        const ZkSafeModule = await ethers.getContractFactory("ZkSafeModule");
        zkSafeModule = await ZkSafeModule.deploy(await verifierContract.getAddress());
        zkSafeModule.waitForDeployment();
        const zkSafeModuleAddress = await zkSafeModule.getAddress();
        console.log("zkSafeModule: ", zkSafeModuleAddress);

        safeAccountConfig.to = zkSafeModuleAddress;

        const height = 32;

        const merkleTree = new MerkleTreeOwners(height);
        await merkleTree.initializePoseidon();
        merkleTree.add(
            await getLeafValue(owners[0])
        );
        merkleTree.add(
            await getLeafValue(owners[1])
        );
        merkleTree.add(
            await getLeafValue(owners[2])
        );
        
        const poseidon = await buildPoseidon();
        const F = poseidon.F;

        const ownersRoot = ethers.toQuantity(F.toObject(merkleTree.getRoot()));
        const iface = new ethers.Interface(["function enableModule(bytes32 ownersRoot, uint256 threshold)"]);
        safeAccountConfig.data = iface.encodeFunctionData("enableModule", [ownersRoot, 2]);

        safe = await safeFactory.deploySafe({ safeAccountConfig });
        const safeAddress = await safe.getAddress();
        console.log("safeAddress", safeAddress);

        // [api, acirComposer, acirBuffer, acirBufferUncompressed] = await initCircuits();

        // New Noir Way
        const backend = new BarretenbergBackend(circuit);
        noir = new Noir(circuit, backend);
        await noir.init();
        console.log("noir backend initialzied");
    });


    it("Should succeed verification of a basic transaction", async function () {

        const nonce = await safe.getNonce();
        const threshold = await safe.getThreshold();
        const safeTransactionData : SafeTransactionData = {
            to: ethers.ZeroAddress,
            value: "0x0",
            data: "0x",
            operation: 0,
            // default fields below
            safeTxGas: "0x0",
            baseGas: "0x0",
            gasPrice: "0x0",
            gasToken: ethers.ZeroAddress,
            refundReceiver: ethers.ZeroAddress,
            nonce, 
        }

        console.log("transaction", safeTransactionData);
        const transaction = await safe.createTransaction({ transactions: [safeTransactionData] });
        const txHash = await safe.getTransactionHash(transaction);
        console.log("txHash", txHash);

        // Let's generate three signatures for the owners of the Safe.
        // ok, our siganture is a EIP-712 signature, so we need to sign the hash of the transaction.
        let safeTypedData = {
            safeAddress: await safe.getAddress(),
            safeVersion: await safe.getContractVersion(),
            chainId: await ownerAdapters[0].getChainId(),
            safeTransactionData: safeTransactionData,
        };

        const nil_pubkey = {
            x: Array.from(ethers.getBytes("0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")),
            y: Array.from(ethers.getBytes("0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8"))
        };
        // Our Nil signature is a signature with r and s set to 
        const nil_signature = Array.from(
            ethers.getBytes("0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8"));

        const owners = (await safe.getOwners());
        
        const merkleTree = new MerkleTreeOwners(32);
        await merkleTree.initializePoseidon();


 	    const poseidon = await buildPoseidon();
        const F = poseidon.F;


        merkleTree.add(
            await getLeafValue(owners[0])
        );
        merkleTree.add(
            await getLeafValue(owners[1])
        );
        merkleTree.add(
            await getLeafValue(owners[2])
        );

        const ownersRoot = F.toObject(merkleTree.getRoot());

        const signatures = [];
        for(let i = 0; i < owners.length; ++i) {
            const sig = await ownerAdapters[i].signTypedData(safeTypedData);
         
            const siblingPath = merkleTree.getProofTreeByIndex(i).map(v => 
                {
                    return (F.toObject(v)).toString();
                });    
           signatures.push({sig, siblingPath, index: i});
        }
        
        // Sort signatures by address - this is how the Safe contract does it.
        signatures.sort((sig1, sig2) => ethers.recoverAddress(txHash, sig1.sig).localeCompare(ethers.recoverAddress(txHash, sig2.sig)));

        const input = {
            threshold: await safe.getThreshold(),
            signers: padArray(signatures.map((sig) => extractCoordinates(ethers.SigningKey.recoverPublicKey(txHash, sig.sig))), 10, nil_pubkey),
            signatures: padArray(signatures.map(s => s.sig).map(extractRSFromSignature), 10, nil_signature),
            txn_hash: Array.from(ethers.getBytes(txHash)),
            owners_root: ownersRoot,
            indices: padArray(signatures.map(s => s.index), 10, 0),
            paths: padArray(signatures.map(s => s.siblingPath), 10, signatures[0].siblingPath)
        };



        // It fails bc: https://github.com/AztecProtocol/aztec-packages/issues/7554
        // But hte proofs runs outside JS
        // const zkSafe: FullNoir = await fullNoirFromCircuit('zkSafe');
        // let { witness, returnValue } = await zkSafe.noir.execute(input);

        // console.log("Generating proof...");
        // const proof: ProofData = await zkSafe.backend.generateProof(witness);
        // console.log(proof);
        // console.log("Verifying proof...");
        // const verification: boolean = await zkSafe.backend.verifyProof(proof);
        // expect(verification).to.be.true;
        // console.log("verification in JS succeeded");


        const proofNow = "0x076afbabf2254d0789169c5ae3c537c0fa9b000fca2451aeaf00ba75154577581e9a997ff5b036696bc8c2ec69d8c44b3570e74ea1cf043bcc3e75f6e13848bc14308fecef5d6389a93bcc884253e4fdf347f69fb0ca4a6face4b38fd0a66d9e120fa4c4e5c60deaf0e367e016d8042801f082a7adac86978eef59045416c14e2c43eaf57129ae1aaa005f5d86242041f4f368be5b2e8c74e47811268b0f837727251a6a3605e8357608ccab58d0813890e7d4fdd7fc03ddfc269e39ea0829f50f4ac142c7bef0b533982c0f4d3c2ec51e1efacf6e60e543787c3621d63d005919dc3d9311b3f3304192bfb88ad8365c8065ea8f23309c0f1b604fcae10104e81e4dda1dc4a7f17bca409a77ac265e05f9cee56a1757baaf0bf5c8496acd1aed00e90bdfd0c3aebb4bc6d92a1cee050b79f59bf33db125cbec51fa99d7b11a0c2bffd0d50a4c4e025b3e7b5d5d7f4b4c908dbc8ba26e94dfeebd50df3e13e2ea0603cfa21877d46830953247ed6d7dc917142ed6f96a04789d1588b1ea31be4f09f20426bc1c8e9a3222a8a365ab50bc89512eec82a6ba88c490712d5291c5602c45fe07c2d4174e21c77bd4f326e777560121c3d1c000f56672f173492ce5cd2ff123ad7724938b9d2567ad390701892f62635b12abd828943725636bcc24f609697b1d12a263595c8f318ef3e119311305be73daf135c90ef860f87f3dab4a0903fca416be93036c47ef543168176e7998f07ead5cbec27ea011a349d488ec2efe64217d135b4ad98b2b08f20b6e1e75f801ea1f16a2785af5f375416c1354087dd1a245d21e5f855e42043ee9a719e2e2743660e5cb3c0439d25f6bab56262d4512aa0b0445ec98e2ee047f43d6109e6e659fb8c61dc6eaeef7ac00197ac907054d57f28e5878ed70da372404d76d180e3f942d70bffaddc761e8f2ec80550c515254d08d682899a72a74b2baea0afb9bf3ce5f0ffea1e9e73d4e64f0bff518460d4f4b4f0b5937d7fd6d43fb7f87cc20acbcc76208da41af15dbebc87dbd2a2fa0780a555bb913e97ebaeafaa403d6bb9462442983e489f36ce816622a6118a8448c899b6c9e3b00413a3af5825b907d5802313338f551ac440a26eacfb12f3fce2e4a765328e853c62ed925bf7c3e2bd9e6d470cfa0eca0485fb4f007992ed4e83e1cc9756d5561a37fb3ef2d953f0e458d48a9c9c06440143a889874bf24c0a2aded4b4e5bee64cd014dbe8201625e28cd362311b46a9538427b63757523b5c17795690fde17280767a38c5c7bccbf05bcb2e0f44acde13188bd54a6fb2e98a7d39a502e091ecb3a1d0e42a7a345cab9ea4e6175adbe76f2a338e0c4ec0ab5b9abc27e2ad8daebb0c95b97d84868bdd5fffdc45c1c10923d9a5b2a1627287b9257e26dc6ad7dec98b061e5821c31b641e2c2e403a64e2e18b94afcc6160a8056836549868824faeb9adc0ab61f2c9d378de9881fcefbf960f4008c2635101253695400cbd4ab7435249a78b5f997dce2c45757aec8a3fcf34b949ed78713a0a796294e5d30a18a296f69906926abce95f44383ea0e4e7c59a3c85ade6e0f392568236e268a7990c358c9f12fd658801c2f7c01c24e9c060eed3b0caa2401f60aa669625ebdf395edeca3f36ea71ddcccb611f5c99feeb62bc668036ee22d7183248d4a64447d90221a3f815012a40b6cf909760ba4498a5e6fc5c4484c116e7775e945d5ec23cf56dd7b5f04ec3629fe520c6c633d429a6dc67ede73531c6e18e753bd4954342f3c0181960f3373b77de5ac2383dd50f1d7933579ca3e0a34513126561467f4d24d9082cd49af3d04277b9a3f3f6ee013719cd8f650092f365d84a22aad2f84aa46e1d32e269df84bac852096d9433c38b6f4174ab9622d37d8ad9b8a377d4394f7ede556c5166ea9e8491e39350b3c60bdf791ae6ee12733b9a5842ed2414d9c9c3309dbe5abdf0ae4100a03002c4597a31f561061bc2a63c0ba880384bf367806e585a22ae482c2b4795a946ade86840da3f5034e2d066d2aeb96a45f07b6d705458962a44c4495f3cd226e695918173fcc6a9109e211a3d84e8e13f2fcde7af9e9cbf7e021b6b9a9f142b05818c0cbb2e86b563c7d2e4c1d37c12d74509983c2270fbf285ee3443d604243b43c55d9ab824254d7830ae270e4c5eff67650de72e98e49b5e10165636cb9cb0278c19003cb642bd15126d738a38a6e1ef3e706cf4e80de77b7b964b87c7199290e67381a05abb4ca921647dbeec82691dd08f3bd8ac2de97c4648335ee94cf609c01433fde9468d461183197e9ba9e76ebb1263cadc15d69a184db68f26491f85392bc758d046ba1410f8c98c2b4880c1cdacbc4939bdb34d047d9ea9464f7766ef02479fe519c51270cb46d4dbc2e5c889780c20cbbea0c5dd4bf97a208160cbe95e2dd29bc14a0c0059834f19480c8dcb4b965c153be01c3864a55f3219ce19d2b1d8bd77200768b0005e5c911129738954296f157aeddfc39b81be280d523814ccb13a9011e18510474a6ba7462997a6b692922a0303644f144f3f02a75f6e7d92547c783541113147631ebefc24e0440708cc123f2933c6a3bf960b56e4010040311c387cc48541889b1c3fa0deac25d2e46c27d4593e358d07b9fbe9c499d0aa51c0cacfde1412a9825224f0789a3d6683afc72b88b803a009d3c71b4da4f185e41d980c47a0f1a256f8952f27843c042580f77061dc2294c61699f862aaf4bf3700e5d18488d2bbdd9aee6d8d1f0de1595713c62552c21129661c7aa06aa7eb42a515e33b9831d58db7d61aea158c57eea5c2b56ac47185144212a223d16f8decf8b6e91651f015f072d44557f068e35e1346702971bffc0aa55d6e618f60a31158cd05cfa0d21426d0c1c024bfd4e95faafd988eecd55ec2abac3bb8dac7a1fc07626f248fd01f0f31f9c5845d42aca0dbed29bed1d99dda91b8cbc1b930588292f262bcb2f0a7b78406b9038569dff5311f8767c612dc106429465045f0407e37f2f9cf5a7";
        const safeAddress = await safe.getAddress();
        //const directVerification = await verifierContract.verify(proof.proof, [...pubInputs]);
        //console.log("directVerification", directVerification);

        const contractVerification = await zkSafeModule.verifyZkSafeTransaction(safeAddress, txHash, proofNow);
        console.log("contractVerification", contractVerification);

        console.log("safe: ", safe);
        console.log("transaction: ", transaction);
        const txn = await zkSafeModule.sendZkSafeTransaction(
            safeAddress,
            { to: transaction["data"]["to"],
              value: BigInt(transaction["data"]["value"]),
              data: transaction["data"]["data"],
              operation: transaction["data"]["operation"],
            },
            proofNow,
            { gasLimit: 2000000 }
        );

        let receipt = txn.wait();
        expect(txn).to.not.be.reverted;
        let newNonce = await safe.getNonce();
        expect(newNonce).to.equal(nonce + 1);
    });

    it("Should fail to verify a nonexistent contract", async function () {

        const transaction  = {
            to: "0x0000000000000000000000000000000000000000",
            value: 0,
            data: "0x",
            operation: 0,
        }

        const txn = zkSafeModule.sendZkSafeTransaction(
            "0x0000000000000000000000000000000000000000",
            transaction,
            "0x", // proof
        );

        expect(txn).to.be.reverted;
    });

    xit("Should fail a basic transaction with a wrong proof", async function () {
        
        const transaction  = {
            to: "0x0000000000000000000000000000000000000000",
            value: 0,
            data: "0x",
            operation: 0,
        }

        const txn = await zkSafeModule.sendZkSafeTransaction(
            await safe.getAddress(),
            transaction,
            "0x0000000000000000", // proof
            { gasLimit: 2000000 }
        );

        expect(txn).to.be.revertedWith("Invalid proof");
    });

    it.skip("Should test recursion", async function() {
        const nonce = await safe.getNonce();
        const safeTransactionData : SafeTransactionData = {
            to: ethers.ZeroAddress,
            value: "0x0",
            data: "0x",
            operation: 0,
            // default fields below
            safeTxGas: "0x0",
            baseGas: "0x0",
            gasPrice: "0x0",
            gasToken: ethers.ZeroAddress,
            refundReceiver: ethers.ZeroAddress,
            nonce, 
        }

        console.log("transaction", safeTransactionData);
        const transaction = await safe.createTransaction({ transactions: [safeTransactionData] });
        const txHash = await safe.getTransactionHash(transaction);
        console.log("txHash", txHash);

        // Let's generate three signatures for the owners of the Safe.
        // ok, our siganture is a EIP-712 signature, so we need to sign the hash of the transaction.
        let safeTypedData = {
            safeAddress: await safe.getAddress(),
            safeVersion: await safe.getContractVersion(),
            chainId: await ownerAdapters[0].getChainId(),
            safeTransactionData: safeTransactionData,
        };

        const nil_pubkey = {
            x: Array.from(ethers.getBytes("0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")),
            y: Array.from(ethers.getBytes("0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8"))
        };
        // Our Nil signature is a signature with r and s set to 
        const nil_signature = Array.from(
            ethers.getBytes("0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8"));

        const owners = (await safe.getOwners());
        
        const merkleTree = new MerkleTreeOwners(32);
        await merkleTree.initializePoseidon();


 	    const poseidon = await buildPoseidon();
        const F = poseidon.F;


        merkleTree.add(
            await getLeafValue(owners[0])
        );
        merkleTree.add(
            await getLeafValue(owners[1])
        );
        merkleTree.add(
            await getLeafValue(owners[2])
        );

        const ownersRoot = F.toObject(merkleTree.getRoot());

        const signatures = [];
        for(let i = 0; i < owners.length; ++i) {
            const sig = await ownerAdapters[i].signTypedData(safeTypedData);
         
            const siblingPath = merkleTree.getProofTreeByIndex(i).map(v => 
                {
                    return (F.toObject(v)).toString();
                });    
           signatures.push({sig, siblingPath, index: i});
        }
        
        // Sort signatures by address - this is how the Safe contract does it.
        signatures.sort((sig1, sig2) => ethers.recoverAddress(txHash, sig1.sig).localeCompare(ethers.recoverAddress(txHash, sig2.sig)));

        const input = {
            signers: padArray(signatures.map((sig) => extractCoordinates(ethers.SigningKey.recoverPublicKey(txHash, sig.sig))), 10, nil_pubkey),
            signatures: padArray(signatures.map(s => s.sig).map(extractRSFromSignature), 10, nil_signature),
            txn_hash: Array.from(ethers.getBytes(txHash)),
            owners_root: ownersRoot,
            indices: padArray(signatures.map(s => s.index), 10, 0),
            paths: padArray(signatures.map(s => s.siblingPath), 10, signatures[0].siblingPath)
        };

        let numPubInputs = 2;

        
        const verify_signers_recursive: FullNoir = await fullNoirFromCircuit('verify_signers_recursive');
        let { witness, returnValue } = await verify_signers_recursive.noir.execute(input);

        // TODO: CONTINUE
    });

});
