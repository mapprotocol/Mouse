// Copyright 2015 The mouse Authors
// This file is part of the mouse library.
//
// The mouse library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The mouse library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the mouse library. If not, see <http://www.gnu.org/licenses/>.

package params

import "github.com/marcopoloprotoco/mouse/common"

// MainnetBootnodes are the enode URLs of the P2P bootstrap nodes running on
// the main Mouse network.
var MainnetBootnodes = []string{
	// Mouse Foundation Go Bootnodes
	"enode://1a53f0d908327e48165333a9ce9547f5461cfdac7f0ca79e588a961913457ebb7004cb543bf40448a32f265206b7abbe176c5c7912264f60ac2027e0652de6de@192.168.3.4:30303", // bootnode-aws-ap-southeast-1-001
}

var MainnetOtherBootnodes = []string{
	// Mouse Foundation Go Bootnodes
	"enode://43b0af23f012289d857d7d0fb800d82943b18739234c9b657dccbc49d90db585ced2c57ad2c082d537edfe2c06bb5de5fe3b7bc4bec41623334a5cef072704bb@39.98.214.163:30164",
	"enode://9425c84c7d265bd1888469b248e0e4bf13512d7b3cea55bf8a1e74b3e6d16f365d3be6a8a68904f302aa47ebbf6608b28c3fc4a4428e3fd12a7d1bbe34a5255e@43.227.254.198:30303",
}

// RopstenBootnodes are the enode URLs of the P2P bootstrap nodes running on the
// Ropsten test network.
var RopstenBootnodes = []string{
	"enode://43b0af23f012289d857d7d0fb800d82943b18739234c9b657dccbc49d90db585ced2c57ad2c082d537edfe2c06bb5de5fe3b7bc4bec41623334a5cef072704bb@39.98.214.163:30164",
	"enode://9425c84c7d265bd1888469b248e0e4bf13512d7b3cea55bf8a1e74b3e6d16f365d3be6a8a68904f302aa47ebbf6608b28c3fc4a4428e3fd12a7d1bbe34a5255e@43.227.254.198:30303",
}

var RopstenOtherBootnodes = []string{}

// MouseBootnodes are the enode URLs of the P2P bootstrap nodes running on
// the main Mouse network.
var MouseBootnodes = []string{
	// Mouse Foundation Go Bootnodes
	"enode://f13a9b42c3a503a2e4dc837a861ba0ae322b86aedf19c58a4e3f0c5ec3c89741d69e1cdc1bd48efc76730ea1a135b7ea3bb79cf84f5d71a92b2c496185d71843@39.98.206.106:30164",
	"enode://43b0af23f012289d857d7d0fb800d82943b18739234c9b657dccbc49d90db585ced2c57ad2c082d537edfe2c06bb5de5fe3b7bc4bec41623334a5cef072704bb@39.98.214.163:30164",
}

// RopstenBootnodes are the enode URLs of the P2P bootstrap nodes running on the
// Ropsten test network.
var DuckBootnodes = []string{
	"enode://829cb1b251260104a186bcdebd426cbe50fa4f247b16f5e8c3abdcb945d03e8d4aeb6fa0b6eebffb9482edfb13eeefa842ebd7c93c6c91f2d00c965033a5f945@47.92.225.192:30164",
	"enode://851b828830f4615380b0b111a1157d4093f672f5a19255257e19504386bdf9ed1a0442e325658b969ff1b93ddc1d100b20a49f7f87147ebd5d34a4a27a527b86@39.98.50.87:30164",
}

// RinkebyBootnodes are the enode URLs of the P2P bootstrap nodes running on the
// Rinkeby test network.
var RinkebyBootnodes = []string{
	"enode://a24ac7c5484ef4ed0c5eb2d36620ba4e4aa13b8c84684e1b4aab0cebea2ae45cb4d375b77eab56516d34bfbd3c1a833fc51296ff084b770b94fb9028c4d25ccf@52.169.42.101:30303", // IE
	"enode://343149e4feefa15d882d9fe4ac7d88f885bd05ebb735e547f12e12080a9fa07c8014ca6fd7f373123488102fe5e34111f8509cf0b7de3f5b44339c9f25e87cb8@52.3.158.184:30303",  // INFURA
	"enode://b6b28890b006743680c52e64e0d16db57f28124885595fa03a562be1d2bf0f3a1da297d56b13da25fb992888fd556d4c1a27b1f39d531bde7de1921c90061cc6@159.89.28.211:30303", // AKASHA
}

var RinkebyOtherBootnodes = []string{
	"enode://a24ac7c5484ef4ed0c5eb2d36620ba4e4aa13b8c84684e1b4aab0cebea2ae45cb4d375b77eab56516d34bfbd3c1a833fc51296ff084b770b94fb9028c4d25ccf@52.169.42.101:30303", // IE
	"enode://343149e4feefa15d882d9fe4ac7d88f885bd05ebb735e547f12e12080a9fa07c8014ca6fd7f373123488102fe5e34111f8509cf0b7de3f5b44339c9f25e87cb8@52.3.158.184:30303",  // INFURA
	"enode://b6b28890b006743680c52e64e0d16db57f28124885595fa03a562be1d2bf0f3a1da297d56b13da25fb992888fd556d4c1a27b1f39d531bde7de1921c90061cc6@159.89.28.211:30303", // AKASHA
}

// GoerliBootnodes are the enode URLs of the P2P bootstrap nodes running on the
// Görli test network.
var GoerliBootnodes = []string{
	// Upstream bootnodes
	"enode://011f758e6552d105183b1761c5e2dea0111bc20fd5f6422bc7f91e0fabbec9a6595caf6239b37feb773dddd3f87240d99d859431891e4a642cf2a0a9e6cbb98a@51.141.78.53:30303",
	"enode://176b9417f511d05b6b2cf3e34b756cf0a7096b3094572a8f6ef4cdcb9d1f9d00683bf0f83347eebdf3b81c3521c2332086d9592802230bf528eaf606a1d9677b@13.93.54.137:30303",
	"enode://46add44b9f13965f7b9875ac6b85f016f341012d84f975377573800a863526f4da19ae2c620ec73d11591fa9510e992ecc03ad0751f53cc02f7c7ed6d55c7291@94.237.54.114:30313",
	"enode://c1f8b7c2ac4453271fa07d8e9ecf9a2e8285aa0bd0c07df0131f47153306b0736fd3db8924e7a9bf0bed6b1d8d4f87362a71b033dc7c64547728d953e43e59b2@52.64.155.147:30303",
	"enode://f4a9c6ee28586009fb5a96c8af13a58ed6d8315a9eee4772212c1d4d9cebe5a8b8a78ea4434f318726317d04a3f531a1ef0420cf9752605a562cfe858c46e263@213.186.16.82:30303",

	// Mouse Foundation bootnode
	"enode://a61215641fb8714a373c80edbfa0ea8878243193f57c96eeb44d0bc019ef295abd4e044fd619bfc4c59731a73fb79afe84e9ab6da0c743ceb479cbb6d263fa91@3.11.147.67:30303",
}

var GoerliOtherBootnodes = []string{
	// Upstream bootnodes
	"enode://011f758e6552d105183b1761c5e2dea0111bc20fd5f6422bc7f91e0fabbec9a6595caf6239b37feb773dddd3f87240d99d859431891e4a642cf2a0a9e6cbb98a@51.141.78.53:30303",
	"enode://176b9417f511d05b6b2cf3e34b756cf0a7096b3094572a8f6ef4cdcb9d1f9d00683bf0f83347eebdf3b81c3521c2332086d9592802230bf528eaf606a1d9677b@13.93.54.137:30303",
	"enode://46add44b9f13965f7b9875ac6b85f016f341012d84f975377573800a863526f4da19ae2c620ec73d11591fa9510e992ecc03ad0751f53cc02f7c7ed6d55c7291@94.237.54.114:30313",
	"enode://c1f8b7c2ac4453271fa07d8e9ecf9a2e8285aa0bd0c07df0131f47153306b0736fd3db8924e7a9bf0bed6b1d8d4f87362a71b033dc7c64547728d953e43e59b2@52.64.155.147:30303",
	"enode://f4a9c6ee28586009fb5a96c8af13a58ed6d8315a9eee4772212c1d4d9cebe5a8b8a78ea4434f318726317d04a3f531a1ef0420cf9752605a562cfe858c46e263@213.186.16.82:30303",

	// Mouse Foundation bootnode
	"enode://a61215641fb8714a373c80edbfa0ea8878243193f57c96eeb44d0bc019ef295abd4e044fd619bfc4c59731a73fb79afe84e9ab6da0c743ceb479cbb6d263fa91@3.11.147.67:30303",
}

// YoloV1Bootnodes are the enode URLs of the P2P bootstrap nodes running on the
// YOLOv1 ephemeral test network.
var YoloV1Bootnodes = []string{
	"enode://9e1096aa59862a6f164994cb5cb16f5124d6c992cdbf4535ff7dea43ea1512afe5448dca9df1b7ab0726129603f1a3336b631e4d7a1a44c94daddd03241587f9@35.178.210.161:30303",
}

var YoloV1OtherBootnodes = []string{
	"enode://9e1096aa59862a6f164994cb5cb16f5124d6c992cdbf4535ff7dea43ea1512afe5448dca9df1b7ab0726129603f1a3336b631e4d7a1a44c94daddd03241587f9@35.178.210.161:30303",
}

const dnsPrefix = "enrtree://AKA3AM6LPBYEUDMVNU3BSVQJ5AD45Y7YPOHJLEF6W26QOE4VTUDPE@"

// KnownDNSNetwork returns the address of a public DNS-based node list for the given
// genesis hash and protocol.
func KnownDNSNetwork(genesis common.Hash, protocol string) string {
	var net string
	switch genesis {
	case MainnetGenesisHash:
		net = "mainnet"
	case RopstenGenesisHash:
		net = "ropsten"
	case RinkebyGenesisHash:
		net = "rinkeby"
	case GoerliGenesisHash:
		net = "goerli"
	default:
		return ""
	}
	return dnsPrefix + protocol + "." + net + ".ethdisco.net"
}
