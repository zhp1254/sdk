import {PrivateKey, VerifyingKey, Account, Address, CREDITS_PROGRAM_KEYS, initThreadPool, ProgramManager, OfflineQuery, OfflineKeyProvider, OfflineSearchParams, ProvingKey, Transaction} from "@provablehq/sdk";
import { getLocalKey, preDownloadBondingKeys, preDownloadTransferKeys } from "./helpers";

await initThreadPool();

/// Build transfer public transaction without connection to the internet
async function buildTransferPublicTxOffline(recipientAddress: Address, amount: number, latestStateRoot: string, keyPaths: {}): Promise<Transaction|Error>  {
    // Create an offline program manager
    const programManager = new ProgramManager();

    // Create a temporary account for the execution of the program
    //const account = new Account();
    
    //APrivateKey1zkpCaSYGYZzxVd5ApeNeX5yPFDPiumZfw6T9bMww2czKurY
    const pKey = PrivateKey.from_string("APrivateKey1zkpCaSYGYZzxVd5ApeNeX5yPFDPiumZfw6T9bMww2czKurY");

    var account = new Account({
        privateKey: pKey.to_string()
    })
    programManager.setAccount(account);


    // Create the proving keys from the key bytes on the offline machine
    console.log("Creating proving keys from local key files");
    const feePublicKeyBytes = await getLocalKey(<string>keyPaths[CREDITS_PROGRAM_KEYS.fee_public.locator]);
    const transferPublicAsSignerKeyBytes = await getLocalKey(<string>keyPaths[CREDITS_PROGRAM_KEYS.transfer_public.locator]);
    const feePublicProvingKey = ProvingKey.fromBytes(feePublicKeyBytes);

    //console.log(feePublicProvingKey.toString())
    const transferPublicProvingKey = ProvingKey.fromBytes(transferPublicAsSignerKeyBytes);



    // Create an offline key provider
    console.log("Creating offline key provider");
    const offlineKeyProvider = new OfflineKeyProvider();

    // Insert the proving keys into the offline key provider. The key provider will automatically insert the verifying
    // keys into the key manager.
    console.log("Inserting proving keys into key provider");
    offlineKeyProvider.insertFeePublicKeys(feePublicProvingKey);
    offlineKeyProvider.insertTransferPublicKeys(transferPublicProvingKey);

    // Create an offline query to complete the inclusion proof
    const offlineQuery = new OfflineQuery(latestStateRoot);

    // Insert the key provider into the program manager
    programManager.setKeyProvider(offlineKeyProvider);

    // Build tne transfer_public transaction offline
    console.log("Building transfer transaction offline");
    return programManager.buildTransferPublicAsSignerTransaction(
        amount,
        recipientAddress.to_string(),
        60000,
        undefined,
        offlineQuery,
    );
}
 

// -------------------ONLINE COMPONENT---------------------
//     (Do this part on an internet connected machine)

// Download the needed keys for the functions we want to execute offline
const transferKeyPaths = await preDownloadTransferKeys();
const bondingKeyPaths = await preDownloadBondingKeys();
//---------------------------------------------------------

// ------------------OFFLINE COMPONENT---------------------
//           (Do this part on an offline machine)
// Get the latest state root from an online machine and enter it into an offline machine
const latestStateRoot = "sr1hm2yjpzegf0me0t3wstmg5w0hrng50avq86ydq5c22ghzqcntyyswhxjcl";

// Build a transfer_public transaction
const stakerAddress = new Account().address();
const validatorAddress = new Account().address();
const withdrawalAddress = new Account().address();
const transferTx = await buildTransferPublicTxOffline(Address.from_string( "aleo17mc3zesnz8a5kukkwpz4cv5lmfw3j5y4xzwucvp33wuskmfzxsqqd82kvv" ), 100000, latestStateRoot, transferKeyPaths);
console.log("Transfer transaction built offline!");
console.log(`\n---------------transfer_public transaction---------------\n${transferTx}`);
console.log(`---------------------------------------------------------`);

//---------------------------------------------------------

// -------------------ONLINE COMPONENT---------------------
//     (Do this part on an internet connected machine)
// ONLINE COMPONENT (Uncomment this part to send the transaction to the Aleo Network on an internet connected machine)
// Submit the transaction to the network
// const transferTxId = await networkClient.submitTransaction(transferTx);
//---------------------------------------------------------
