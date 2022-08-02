//  web3swift
//
//  Created by Alex Vlasov.
//  Copyright © 2018 Alex Vlasov. All rights reserved.
//

import BigInt
import Foundation

extension Web3.TxPool {
    public func getInspect() async throws -> [String: [String: [String: String]]] {
        let result = try await self.txPoolInspect()
        return result
    }

    public func getStatus() async throws -> TxPoolStatus {
        let result = try await self.txPoolStatus()
        return result
    }

    public func getContent() async throws -> TxPoolContent {
        let result = try await self.txPoolContent()
        return result
    }
}
