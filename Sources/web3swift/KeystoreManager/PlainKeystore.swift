//  web3swift
//
//  Created by Alex Vlasov.
//  Copyright © 2018 Alex Vlasov. All rights reserved.
//

import Foundation
import CryptoSwift

public class PlainKeystore: AbstractKeystore {

    public var isHDKeystore = false

    private var privateKey: Data

    public var addresses: [EthereumAddress]?

    public var keystoreParams: KeystoreParamsV3?

    public func UNSAFE_getPrivateKeyData(password: String = "", account: EthereumAddress) throws -> Data {
        self.privateKey
    }

    public convenience init?(privateKey: String) {
        guard let privateKeyData = Data.fromHex(privateKey) else {return nil}
        self.init(privateKey: privateKeyData)
    }

    public init?(privateKey: Data, password: String = "web3swift") {
        guard SECP256K1.verifyPrivateKey(privateKey: privateKey) else {return nil}
        guard let publicKey = Web3.Utils.privateToPublic(privateKey, compressed: false) else {return nil}
        guard let address = Web3.Utils.publicToAddress(publicKey) else {return nil}
        self.addresses = [address]
        self.privateKey = privateKey
        try? encryptDataToStorage(password, keyData: privateKey)
    }

    fileprivate func encryptDataToStorage(_ password: String, keyData: Data?, dkLen: Int = 32, N: Int = 4096, R: Int = 6, P: Int = 1, aesMode: String = "aes-128-cbc") throws {
        // swiftlint:disable indentation_width
        guard let keyData = keyData else {
            throw AbstractKeystoreError.encryptionError("Encryption without key data")
        }
        let saltLen = 32
        guard let saltData = Data.randomBytes(length: saltLen),
              let derivedKey = scrypt(password: password, salt: saltData, length: dkLen, N: N, R: R, P: P),
              let IV = Data.randomBytes(length: 16)
        else {
            throw AbstractKeystoreError.keyDerivationError
        }
        let last16bytes = Data(derivedKey[(derivedKey.count - 16)...(derivedKey.count - 1)])
        let encryptionKey = Data(derivedKey[0...15])

        var aesCipher: AES?
        switch aesMode {
        case "aes-128-cbc":
            aesCipher = try? AES(key: encryptionKey.bytes, blockMode: CBC(iv: IV.bytes), padding: .noPadding)
        case "aes-128-ctr":
            aesCipher = try? AES(key: encryptionKey.bytes, blockMode: CTR(iv: IV.bytes), padding: .noPadding)
        default:
            aesCipher = nil
        }
        if aesCipher == nil {
            throw AbstractKeystoreError.aesError
        }
        guard let encryptedKey = try aesCipher?.encrypt(keyData.bytes) else {
            throw AbstractKeystoreError.aesError
        }
        let encryptedKeyData = Data(encryptedKey)
        var dataForMAC = Data()
        dataForMAC.append(last16bytes)
        dataForMAC.append(encryptedKeyData)
        let mac = dataForMAC.sha3(.keccak256)
        let kdfparams = KdfParamsV3(salt: saltData.toHexString(), dklen: dkLen, n: N, p: P, r: R, c: nil, prf: nil)
        let cipherparams = CipherParamsV3(iv: IV.toHexString())
        let crypto = CryptoParamsV3(ciphertext: encryptedKeyData.toHexString(), cipher: aesMode, cipherparams: cipherparams, kdf: "scrypt", kdfparams: kdfparams, mac: mac.toHexString(), version: nil)
        guard let pubKey = Web3.Utils.privateToPublic(keyData) else {
            throw AbstractKeystoreError.keyDerivationError
        }
        guard let addr = Web3.Utils.publicToAddress(pubKey) else {
            throw AbstractKeystoreError.keyDerivationError
        }
        self.addresses = [addr]
        let keystoreparams = KeystoreParamsV3(address: addr.address.lowercased(), crypto: crypto, id: UUID().uuidString.lowercased(), version: 3)
        self.keystoreParams = keystoreparams
    }
}
