//
//  ViewController.swift
//  web3swiftExample
//
//  Created by Alexander Vlasov on 22.12.2017.
//  Copyright © 2017 Alexander Vlasov. All rights reserved.
//

import UIKit
import BigInt
import web3swift
import Foundation


extension KeystoreManager {

    fileprivate func saveKeyStore(_ key: EthereumKeystoreV3) -> Bool {
        guard let keyData = try? JSONEncoder().encode(key.keystoreParams),
            let address = key.getAddress()?.address else {
            return false
        }
        let ret = FileManager.default.createFile(atPath: self.path + "/\(address).json", contents: keyData, attributes: nil)
        do {
            try self.updateKeyStores()
        } catch {
            return false
        }
        return ret
    }

    fileprivate func removeLocalAccount(address: EthereumAddress) -> Bool {
        return false
    }
}

class ViewController: UIViewController {

    fileprivate static let jsonString = "[{\"constant\":true,\"inputs\":[],\"name\":\"name\",\"outputs\":[{\"name\":\"\",\"type\":\"string\"}],\"payable\":false,\"type\":\"function\"},{\"constant\":false,\"inputs\":[{\"name\":\"_spender\",\"type\":\"address\"},{\"name\":\"_value\",\"type\":\"uint256\"}],\"name\":\"approve\",\"outputs\":[{\"name\":\"success\",\"type\":\"bool\"}],\"payable\":false,\"type\":\"function\"},{\"constant\":true,\"inputs\":[],\"name\":\"totalSupply\",\"outputs\":[{\"name\":\"\",\"type\":\"uint256\"}],\"payable\":false,\"type\":\"function\"},{\"constant\":false,\"inputs\":[{\"name\":\"_from\",\"type\":\"address\"},{\"name\":\"_to\",\"type\":\"address\"},{\"name\":\"_value\",\"type\":\"uint256\"}],\"name\":\"transferFrom\",\"outputs\":[{\"name\":\"success\",\"type\":\"bool\"}],\"payable\":false,\"type\":\"function\"},{\"constant\":true,\"inputs\":[],\"name\":\"decimals\",\"outputs\":[{\"name\":\"\",\"type\":\"uint8\"}],\"payable\":false,\"type\":\"function\"},{\"constant\":true,\"inputs\":[],\"name\":\"version\",\"outputs\":[{\"name\":\"\",\"type\":\"string\"}],\"payable\":false,\"type\":\"function\"},{\"constant\":true,\"inputs\":[{\"name\":\"_owner\",\"type\":\"address\"}],\"name\":\"balanceOf\",\"outputs\":[{\"name\":\"balance\",\"type\":\"uint256\"}],\"payable\":false,\"type\":\"function\"},{\"constant\":true,\"inputs\":[],\"name\":\"symbol\",\"outputs\":[{\"name\":\"\",\"type\":\"string\"}],\"payable\":false,\"type\":\"function\"},{\"constant\":false,\"inputs\":[{\"name\":\"_to\",\"type\":\"address\"},{\"name\":\"_value\",\"type\":\"uint256\"}],\"name\":\"transfer\",\"outputs\":[{\"name\":\"success\",\"type\":\"bool\"}],\"payable\":false,\"type\":\"function\"},{\"constant\":false,\"inputs\":[{\"name\":\"_spender\",\"type\":\"address\"},{\"name\":\"_value\",\"type\":\"uint256\"},{\"name\":\"_extraData\",\"type\":\"bytes\"}],\"name\":\"approveAndCall\",\"outputs\":[{\"name\":\"success\",\"type\":\"bool\"}],\"payable\":false,\"type\":\"function\"},{\"constant\":true,\"inputs\":[{\"name\":\"_owner\",\"type\":\"address\"},{\"name\":\"_spender\",\"type\":\"address\"}],\"name\":\"allowance\",\"outputs\":[{\"name\":\"remaining\",\"type\":\"uint256\"}],\"payable\":false,\"type\":\"function\"},{\"inputs\":[{\"name\":\"_initialAmount\",\"type\":\"uint256\"},{\"name\":\"_tokenName\",\"type\":\"string\"},{\"name\":\"_decimalUnits\",\"type\":\"uint8\"},{\"name\":\"_tokenSymbol\",\"type\":\"string\"}],\"type\":\"constructor\"},{\"payable\":false,\"type\":\"fallback\"},{\"anonymous\":false,\"inputs\":[{\"indexed\":true,\"name\":\"_from\",\"type\":\"address\"},{\"indexed\":true,\"name\":\"_to\",\"type\":\"address\"},{\"indexed\":false,\"name\":\"_value\",\"type\":\"uint256\"}],\"name\":\"Transfer\",\"type\":\"event\"},{\"anonymous\":false,\"inputs\":[{\"indexed\":true,\"name\":\"_owner\",\"type\":\"address\"},{\"indexed\":true,\"name\":\"_spender\",\"type\":\"address\"},{\"indexed\":false,\"name\":\"_value\",\"type\":\"uint256\"}],\"name\":\"Approval\",\"type\":\"event\"},]"

    fileprivate static let ropstenTestAccountAddress = "0x113e67175e36f3201288dbba836baf1a701ed8b2"
    fileprivate static let ropstenTestBlocContractAddress = "0x097544ccc24766aff1bf3a78a219c8e1e304be14"

    @IBOutlet weak var imageView: UIImageView!
    override func viewDidLoad() {
        super.viewDidLoad()
        

        // tests
//        assert(self.testRopstenBalance())
//        assert(self.testRopstenBlocTokenBalance())
//        assert(self.testRopstenBlocTokenTransfer())

        // create normal keystore
        
        let userDir = NSSearchPathForDirectoriesInDomains(.documentDirectory, .userDomainMask, true)[0]
        let keystoreManager = KeystoreManager.managerForPath(userDir + "/12345/keystore")
        var ks: EthereumKeystoreV3?
        if (keystoreManager?.addresses?.count == 0) {
            ks = try! EthereumKeystoreV3(password: "BANKEXFOUNDATION")
            print("ret = \(String(describing: keystoreManager?.saveKeyStore(ks!)))")
        } else {
            ks = keystoreManager?.walletForAddress((keystoreManager?.addresses![0])!) as! EthereumKeystoreV3
        }
        guard let sender = ks?.addresses?.first else {return}
        print(sender)
    
        //create BIP32 keystore
        let bip32keystoreManager = KeystoreManager.managerForPath(userDir + "/bip32_keystore", scanForHDwallets: true)
        var bip32ks: BIP32Keystore?
        if (bip32keystoreManager?.addresses?.count == 0) {
            bip32ks = try! BIP32Keystore.init(mnemonics: "normal dune pole key case cradle unfold require tornado mercy hospital buyer", password: "BANKEXFOUNDATION", mnemonicsPassword: "", language: .english)
            let keydata = try! JSONEncoder().encode(bip32ks!.keystoreParams)
            FileManager.default.createFile(atPath: userDir + "/bip32_keystore"+"/key.json", contents: keydata, attributes: nil)
        } else {
            bip32ks = bip32keystoreManager?.walletForAddress((bip32keystoreManager?.addresses![0])!) as! BIP32Keystore
        }
        guard let bip32sender = bip32ks?.addresses?.first else {return}
        print(bip32sender)
        
        
        // BKX TOKEN
        let web3Main = Web3.InfuraMainnetWeb3()
        let coldWalletAddress = EthereumAddress("0x6394b37Cf80A7358b38068f0CA4760ad49983a1B")!
        let constractAddress = EthereumAddress("0x45245bc59219eeaaf6cd3f382e078a461ff9de7b")!
        let gasPriceResult = web3Main.eth.getGasPrice()
        guard case .success(let gasPrice) = gasPriceResult else {return}
        var options = Web3Options.defaultOptions()
        options.gasPrice = gasPrice
        options.from = EthereumAddress("0xE6877A4d8806e9A9F12eB2e8561EA6c1db19978d")!
        let parameters = [] as [AnyObject]
        
        web3Main.addKeystoreManager(keystoreManager)
        let contract = web3Main.contract(ViewController.jsonString, at: constractAddress, abiVersion: 2)!
        let intermediate = contract.method("name", parameters:parameters,  options: options)
        guard let tokenNameRes = intermediate?.call(options: options) else {return}
        guard case .success(let result) = tokenNameRes else {return}
        print("BKX token name = " + (result["0"] as! String))
    
        guard let bkxBalanceResult = contract.method("balanceOf", parameters: [coldWalletAddress] as [AnyObject], options: options)?.call(options: nil) else {return}
        guard case .success(let bkxBalance) = bkxBalanceResult, let bal = bkxBalance["0"] as? BigUInt else {return}
        print("BKX token balance = " + String(bal))
        
        // Test token transfer on Rinkeby
        
        
        var eip67Data = Web3.EIP67Code.init(address: EthereumAddress("0x6394b37Cf80A7358b38068f0CA4760ad49983a1B")!)
        eip67Data.gasLimit = BigUInt(21000)
        eip67Data.amount = BigUInt("1000000000000000000")
        //        eip67Data.data =
        let encoding = eip67Data.toImage(scale: 10.0)
        self.imageView.image = UIImage(ciImage: encoding)
        self.imageView.contentMode = .scaleAspectFit
        
        //Send on Rinkeby using normal keystore
        
        let web3Rinkeby = Web3.InfuraRinkebyWeb3()
        web3Rinkeby.addKeystoreManager(keystoreManager)
        let coldWalletABI = "[{\"payable\":true,\"type\":\"fallback\"}]"
        options = Web3Options.defaultOptions()
        options.gasLimit = BigUInt(21000)
        options.from = ks?.addresses?.first!
        options.value = BigUInt(1000000000000000)
        options.from = sender
        let estimatedGasResult = web3Rinkeby.contract(coldWalletABI, at: coldWalletAddress)!.method(options: options)!.estimateGas(options: nil)
        guard case .success(let estimatedGas) = estimatedGasResult else {return}
        options.gasLimit = estimatedGas
        var intermediateSend = web3Rinkeby.contract(coldWalletABI, at: coldWalletAddress, abiVersion: 2)!.method(options: options)!
        let sendResult = intermediateSend.send(password: "BANKEXFOUNDATION")
//        let derivedSender = intermediateSend.transaction.sender
//        if (derivedSender?.address != sender.address) {
//            print(derivedSender!.address)
//            print(sender.address)
//            print("Address mismatch")
//        }
        guard case .success(let sendingResult) = sendResult else {return}
        let txid = sendingResult.hash
        print("On Rinkeby TXid = " + txid)
        
        //Send ETH on Rinkeby using BIP32 keystore. Should fail due to insufficient balance
        web3Rinkeby.addKeystoreManager(bip32keystoreManager)
        options.from = bip32ks?.addresses?.first!
        intermediateSend = web3Rinkeby.contract(coldWalletABI, at: coldWalletAddress, abiVersion: 2)!.method(options: options)!
        let sendResultBip32 = intermediateSend.send(password: "BANKEXFOUNDATION")
        switch sendResultBip32 {
        case .success(let r):
            print(r)
        case .failure(let err):
            print(err)
        }
        
        //Send ERC20 token on Rinkeby
        guard case .success(let gasPriceRinkeby) = web3Rinkeby.eth.getGasPrice() else {return}
        web3Rinkeby.addKeystoreManager(keystoreManager)
        var tokenTransferOptions = Web3Options.defaultOptions()
        tokenTransferOptions.gasPrice = gasPriceRinkeby
        tokenTransferOptions.from = ks?.addresses?.first!
        let testToken = web3Rinkeby.contract(Web3.Utils.erc20ABI, at: EthereumAddress("0xa407dd0cbc9f9d20cdbd557686625e586c85b20a")!, abiVersion: 2)!
        let intermediateForTokenTransfer = testToken.method("transfer", parameters: [EthereumAddress("0x6394b37Cf80A7358b38068f0CA4760ad49983a1B")!, BigUInt(1)] as [AnyObject], options: tokenTransferOptions)!
        let gasEstimateResult = intermediateForTokenTransfer.estimateGas(options: nil)
        guard case .success(let gasEstimate) = gasEstimateResult else {return}
        var optionsWithCustomGasLimit = Web3Options()
        optionsWithCustomGasLimit.gasLimit = gasEstimate
        let tokenTransferResult = intermediateForTokenTransfer.send(password: "BANKEXFOUNDATION", options: optionsWithCustomGasLimit)
        switch tokenTransferResult {
        case .success(let res):
            print("Token transfer successful")
            print(res)
        case .failure(let error):
            print(error)
        }
        
        //Send ERC20 on Rinkeby using a convenience function
        var convenienceTransferOptions = Web3Options.defaultOptions()
        convenienceTransferOptions.gasPrice = gasPriceRinkeby
        let convenienceTokenTransfer = web3Rinkeby.eth.sendERC20tokensWithNaturalUnits(tokenAddress: EthereumAddress("0xa407dd0cbc9f9d20cdbd557686625e586c85b20a")!, from: (ks?.addresses?.first!)!, to: EthereumAddress("0x6394b37Cf80A7358b38068f0CA4760ad49983a1B")!, amount: "0.0001", options: convenienceTransferOptions)
        let gasEstimateResult2 = convenienceTokenTransfer!.estimateGas(options: nil)
        guard case .success(let gasEstimate2) = gasEstimateResult2 else {return}
        convenienceTransferOptions.gasLimit = gasEstimate2
        let convenienceTransferResult = convenienceTokenTransfer!.send(password: "BANKEXFOUNDATION", options: convenienceTransferOptions)
        switch convenienceTransferResult {
        case .success(let res):
            print("Token transfer successful")
            print(res)
        case .failure(let error):
            print(error)
        }
        
        //Balance on Rinkeby
        let balanceResult = web3Rinkeby.eth.getBalance(address: coldWalletAddress)
        guard case .success(let balance) = balanceResult else {return}
        print("Balance of " + coldWalletAddress.address + " = " + String(balance))
        
//                Send mutating transaction taking parameters
        let testABIonRinkeby = "[{\"constant\":true,\"inputs\":[],\"name\":\"counter\",\"outputs\":[{\"name\":\"\",\"type\":\"uint8\"}],\"payable\":false,\"stateMutability\":\"view\",\"type\":\"function\"},{\"constant\":false,\"inputs\":[{\"name\":\"_value\",\"type\":\"uint8\"}],\"name\":\"increaseCounter\",\"outputs\":[],\"payable\":false,\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"inputs\":[],\"payable\":false,\"stateMutability\":\"nonpayable\",\"type\":\"constructor\"}]"
        let deployedTestAddress = EthereumAddress("0x1e528b190b6acf2d7c044141df775c7a79d68eba")!
        options = Web3Options.defaultOptions()
        options.gasLimit = BigUInt(100000)
        options.value = BigUInt(0)
        options.from = ks?.addresses![0]
        let testParameters = [BigUInt(1)] as [AnyObject]
        let testMutationResult = web3Rinkeby.contract(testABIonRinkeby, at: deployedTestAddress, abiVersion: 2)?.method("increaseCounter", parameters: testParameters, options: options)?.send(password: "BANKEXFOUNDATION")
        print(testMutationResult)
    }
}

//MARK: - Tests
extension ViewController {
    fileprivate func testRopstenCreateAccount() -> Bool {
        //check testnet account's balance
        let w3 = Web3.InfuraRopstenWeb3()
//        w3.wallet.getAccounts()
        return true
    }

    fileprivate func testRopstenBalance() -> Bool {
        //check testnet account's balance
        let w3 = Web3.InfuraRopstenWeb3()
        let address = EthereumAddress("0x0552ece35b227a40733fd443d08dfa6215443315")!
        let balanceResult = w3.eth.getBalance(address: address)
        guard case .success(let balance) = balanceResult else {return false}
        print("balance of \(address.address): \(balance.description)")
        return true
    }

    fileprivate func testRopstenBlocTokenBalance() -> Bool {
        //check testnet account's bloc token balance
        let w3 = Web3.InfuraRopstenWeb3()
        let address = EthereumAddress(ViewController.ropstenTestAccountAddress)!
        let contractAddress = EthereumAddress(ViewController.ropstenTestBlocContractAddress)!
        let contract = w3.contract(ViewController.jsonString, at: contractAddress, abiVersion: 2)!

        let gasPriceResult = w3.eth.getGasPrice()
        guard case .success(let gasPrice) = gasPriceResult else {return false}

        var options = Web3Options.defaultOptions()
        options.gasPrice = gasPrice
        options.from = EthereumAddress(ViewController.ropstenTestAccountAddress)!

        let symbolMethod = contract.method("symbol", parameters: [], options:options)
        guard let tokenSymbolRes = symbolMethod?.call(options: options) else { return false }
        guard case .success(let tokenSymbolResult) = tokenSymbolRes else {return false}
        print("token symbol: \(tokenSymbolResult["0"] as! String)")

        let nameMethod = contract.method("name", parameters:[],  options: options)
        guard let tokenNameRes = nameMethod?.call(options: options) else {return false}
        guard case .success(let tokenNameResult) = tokenNameRes else {return false}
        print("token name = " + (tokenNameResult["0"] as! String))

        guard let balanceResult = contract.method("balanceOf", parameters: [address] as [AnyObject], options: options)?.call(options: nil) else {return false}
        guard case .success(let balance) = balanceResult, let bal = balance["0"] as? BigUInt else {return false}
        print("token balance = " + String(bal))

        return true
    }

    fileprivate func testRopstenBlocTokenTransfer() -> Bool {
        //TODO: Not done yet.
        return true
    }
}

