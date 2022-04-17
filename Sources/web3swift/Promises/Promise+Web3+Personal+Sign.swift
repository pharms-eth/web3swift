//  web3swift
//
//  Created by Alex Vlasov.
//  Copyright © 2018 Alex Vlasov. All rights reserved.
//

import Foundation
import BigInt


extension web3.Personal {

    public func signPersonal(message: Data, from: EthereumAddress, password: String = "web3swift") async throws -> Data {

        guard let attachedKeystoreManager = self.web3.provider.attachedKeystoreManager else {
            let hexData = message.toHexString().addHexPrefix()
            let request = JSONRPCRequestFabric.prepareRequest(.personalSign, parameters: [from.address.lowercased(), hexData])

            let response = try await self.web3.dispatch(request)

            guard let value: Data = response.getValue() else {
                if response.error != nil {
                    throw Web3Error.nodeError(desc: response.error!.message)
                }
                throw Web3Error.nodeError(desc: "Invalid value from Ethereum node")
            }
            return value
        }


        guard let signature = try Web3Signer.signPersonalMessage(message, keystore: attachedKeystoreManager, account: from, password: password) else {
            throw Web3Error.inputError(desc: "Failed to locally sign a message")
        }

        return signature
    }
}
