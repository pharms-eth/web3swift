//
// Created by Petr Korolev on 26.10.2020.
//

import Foundation

public struct KdfParamsV3: Decodable, Encodable {
    public var salt: String
    public var dklen: Int
    public var n: Int?
    public var p: Int?
    public var r: Int?
    public var c: Int?
    public var prf: String?
}

public struct CipherParamsV3: Decodable, Encodable {
    public var iv: String
}

public struct CryptoParamsV3: Decodable, Encodable {
    public var ciphertext: String
    public var cipher: String
    public var cipherparams: CipherParamsV3
    public var kdf: String
    public var kdfparams: KdfParamsV3
    public var mac: String
    public var version: String?
}

public protocol AbstractKeystoreParams: Codable {
    var crypto: CryptoParamsV3 { get }
    var id: String? { get }
    var version: Int { get }
    var isHDWallet: Bool { get }

}

public struct PathAddressPair: Codable {
    public let path: String
    public let address: String
}

public struct KeystoreParamsBIP32: AbstractKeystoreParams {
    public var crypto: CryptoParamsV3
    public var id: String?
    public var version: Int
    public var isHDWallet: Bool

    @available(*, deprecated, message: "Please use pathAddressPairs instead")
    var pathToAddress: [String: String] {
        get {
            self.pathAddressPairs.reduce(into: [String: String]()) {
                $0[$1.path] = $1.address
            }
        }
        set {
            for pair in newValue {
                self.pathAddressPairs.append(PathAddressPair(path: pair.0, address: pair.1))
            }
        }
    }

    public var pathAddressPairs: [PathAddressPair]
    public var rootPath: String?

    public init(crypto cr: CryptoParamsV3, id i: String, version ver: Int = 32, rootPath: String? = nil) {
        self.crypto = cr
        self.id = i
        self.version = ver
        pathAddressPairs = [PathAddressPair]()
        self.rootPath = rootPath
        self.isHDWallet = true
    }

}

public struct KeystoreParamsV3: AbstractKeystoreParams {
    public var crypto: CryptoParamsV3
    public var id: String?
    public var version: Int
    public var isHDWallet: Bool

    public var address: String?

    public init(address ad: String?, crypto cr: CryptoParamsV3, id i: String, version ver: Int) {
        address = ad
        self.crypto = cr
        self.id = i
        self.version = ver
        self.isHDWallet = false
    }

}
