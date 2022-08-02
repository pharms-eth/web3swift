//
//  OracleTests.swift
//  Web3swift
//
//  Created by Yaroslav on 11.04.2022.
//

import XCTest
import BigInt

@testable import web3swift

// MARK: Works only with network connection
class OracleTests: XCTestCase {



    let blockNumber: BigUInt = 14571792



    func testPretictBaseFee() async throws {
        let web3 = await Web3.InfuraMainnetWeb3(accessToken: Constants.infuraToken)
        lazy var oracle: Web3.Oracle = .init(web3, block: .exact(blockNumber), blockCount: 20, percentiles: [10, 40, 60, 90])
        let etalonPercentiles: [BigUInt] = [
            71456911562,    // 10 percentile
            92735433497,    // 40 percentile
            105739785122,   // 60 percentile
            118929912191    // 90 percentile
        ]

        let baseFeePercentiles = await oracle.baseFeePercentiles()
        XCTAssertEqual(baseFeePercentiles, etalonPercentiles, "Arrays should be equal")
    }

    func testPredictTip() async throws {
        let web3 = await Web3.InfuraMainnetWeb3(accessToken: Constants.infuraToken)
        lazy var oracle: Web3.Oracle = .init(web3, block: .exact(blockNumber), blockCount: 20, percentiles: [10, 40, 60, 90])
        let etalonPercentiles: [BigUInt] = [
            1251559157,     // 10 percentile
            1594062500,     // 40 percentile
            2268157275,     // 60 percentile
            11394017894     // 90 percentile
        ]

        let tipFeePercentiles = await oracle.tipFeePercentiles()
        XCTAssertEqual(tipFeePercentiles, etalonPercentiles, "Arrays should be equal")
    }

    func testPredictBothFee() async throws {
        let web3 = await Web3.InfuraMainnetWeb3(accessToken: Constants.infuraToken)
        lazy var oracle: Web3.Oracle = .init(web3, block: .exact(blockNumber), blockCount: 20, percentiles: [10, 40, 60, 90])
        let etalonPercentiles: ([BigUInt], [BigUInt]) = (
            baseFee: [
                71456911562,    // 10 percentile
                92735433497,    // 40 percentile
                105739785122,   // 60 percentile
                118929912191    // 90 percentile
            ],
            tip: [
                1251559157,     // 10 percentile
                1594062500,     // 40 percentile
                2268157275,     // 60 percentile
                11394017894     // 90 percentile
            ]
        )

        let bothFeesPercentiles = await oracle.bothFeesPercentiles()
        XCTAssertEqual(bothFeesPercentiles?.baseFee, etalonPercentiles.0, "Arrays should be equal")
        XCTAssertEqual(bothFeesPercentiles?.tip, etalonPercentiles.1, "Arrays should be equal")
    }

    func testPredictLegacyGasPrice() async throws {
        let web3 = await Web3.InfuraMainnetWeb3(accessToken: Constants.infuraToken)
        lazy var oracle: Web3.Oracle = .init(web3, block: .exact(blockNumber), blockCount: 20, percentiles: [10, 40, 60, 90])
        let etalonPercentiles: [BigUInt] = [
            93253857566,     // 10 percentile
            106634912620,    // 40 percentile
            111000000000,    // 60 percentile
            127210686305     // 90 percentile
        ]
        
        let gasPriceLegacyPercentiles = await oracle.gasPriceLegacyPercentiles()
        XCTAssertEqual(gasPriceLegacyPercentiles, etalonPercentiles, "Arrays should be equal")
    }

    func testAllTransactionInBlockDecodesWell() async throws {
        let web3 = await Web3.InfuraMainnetWeb3(accessToken: Constants.infuraToken)
        lazy var oracle: Web3.Oracle = .init(web3, block: .exact(blockNumber), blockCount: 20, percentiles: [10, 40, 60, 90])
        let blockWithTransaction = try await web3.eth.getBlockByNumber(blockNumber, fullTransactions: true)

        let nullTransactions = blockWithTransaction.transactions.filter {
            guard case .null = $0 else { return false }
            return true
        }

        XCTAssert(nullTransactions.isEmpty, "This amount transaction fails to decode: \(nullTransactions.count)")
    }
}
