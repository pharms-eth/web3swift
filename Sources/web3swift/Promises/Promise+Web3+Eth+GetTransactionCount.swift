//  web3swift
//
//  Created by Alex Vlasov.
//  Copyright © 2018 Alex Vlasov. All rights reserved.
//

import Foundation
import BigInt


extension web3.Eth {
    public func getTransactionCount(for address: EthereumAddress, onBlock: String = "latest") async throws -> BigUInt {
        let addr = address.address
        return try await getTransactionCount(address: addr, onBlock: onBlock)
    }

    public func getTransactionCount(address: String, onBlock: String = "latest") async throws -> BigUInt {
        let request = JSONRPCRequestFabric.prepareRequest(.getTransactionCount, parameters: [address.lowercased(), onBlock])
        let response = try await web3.dispatch(request)

        guard let value: BigUInt = response.getValue() else {
            if response.error != nil {
                throw Web3Error.nodeError(desc: response.error!.message)
            }
            throw Web3Error.nodeError(desc: "Invalid value from Ethereum node")
        }
        return value
    }
}
