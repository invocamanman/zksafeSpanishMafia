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
        
        const ownersRoot = merkleTree.getRoot();
        
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
        const zero_address = new Array(20).fill(0);

        const owners = (await safe.getOwners());
        
        const merkleTree = new MerkleTreeOwners(32);
        await merkleTree.initializePoseidon();

        const hola = await getLeafValue(owners[1]);


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

        
        const zkSafe: FullNoir = await fullNoirFromCircuit('zkSafe');
        let { witness, returnValue } = await zkSafe.noir.execute(input);

        console.log("Generating proof...");
        const proof: ProofData = await zkSafe.backend.generateProof(witness);
        console.log(proof);
        console.log("Verifying proof...");
        const verification: boolean = await zkSafe.backend.verifyProof(proof);
        expect(verification).to.be.true;
        console.log("verification in JS succeeded");


        const safeAddress = await safe.getAddress();
        const directVerification = await verifierContract.verify(proof.proof, [...proof.publicInputs.values()]);
        console.log("directVerification", directVerification);

        const contractVerification = await zkSafeModule.verifyZkSafeTransaction(safeAddress, txHash, proof.proof);
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
            proof.proof,
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

});
