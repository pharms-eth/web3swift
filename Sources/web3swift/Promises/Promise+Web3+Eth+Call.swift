//  web3swift
//
//  Created by Alex Vlasov.
//  Copyright © 2018 Alex Vlasov. All rights reserved.
//

import Foundation


extension web3.Eth {

    public func callTransaction(_ transaction: EthereumTransaction, transactionOptions: TransactionOptions?) async throws -> Data {
        guard let request = EthereumTransaction.createRequest(method: .call, transaction: transaction, transactionOptions: transactionOptions) else {
            throw Web3Error.processingError(desc: "Transaction is invalid")
        }
        let response = try await web3.dispatch(request)

        guard let value: Data = response.getValue() else {
            if response.error != nil {
                throw Web3Error.nodeError(desc: response.error!.message)
            }
            throw Web3Error.nodeError(desc: "Invalid value from Ethereum node")
        }
        return value
    }
}
