//  web3swift
//
//  Created by Alex Vlasov.
//  Copyright © 2018 Alex Vlasov. All rights reserved.
//

import BigInt
import Foundation

extension Web3.Eth {
    public func getTransactionCount(for address: EthereumAddress, onBlock: String = "latest") async throws -> BigUInt {
        let addr = address.address
        return try await getTransactionCount(address: addr, onBlock: onBlock)
    }

    public func getTransactionCount(address: String, onBlock: String = "latest") async throws -> BigUInt {
        let request = JSONRPCRequestFabric.prepareRequest(.getTransactionCount, parameters: [address.lowercased(), onBlock])
        let response = try await web3.dispatch(request)

        guard let value: BigUInt = response.getValue() else {
            throw Web3Error.nodeError(desc: response.error?.message ?? "Invalid value from Ethereum node")
        }
        return value
    }
}
