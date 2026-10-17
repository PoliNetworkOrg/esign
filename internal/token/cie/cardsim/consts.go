package cardsim

import "math/big"

// The real CV root key's modulus is only on the cards. rootN and rootE form an RSA key for which the reference's
// fixed root private exponent (ias.RootPrivExp, from the official ExtAuthKey.cpp) is a valid private exponent:
// rootN = p*q was drawn at random and rootE = RootPrivExp^-1 mod lcm(p-1, q-1). With it, a terminal certificate made
// by unmodified reference code verifies on the simulator exactly as on a card.
var (
	rootN = mustInt("" +
		"d4dd85a1584c43524bac226faba4ebf294fa4e97f5463f61b21089cbdd34d993dd7af50b36d3a1589bedc1f68f91be79" +
		"dc50e467e6c40297395803730afc04edaea1be42d461d99c8fac6d52f98d57eed74729c1b1b6d334f1f7370587c81897" +
		"c3a23fdf852bfc88829b9b99db4fb3eb6f2ca136428670d42096c75f91ec3e9fc1bc08b6ea7faa59a0557580cb77780b" +
		"9862d5f43efc05280f420bfcc9c7f1aa467db41ed72d04aa5425471d9e82a4da2d84fca9365d58d25ad1716a2ec7e00f" +
		"1a50f3b99cbd9b0ca85c3ae5c0a75fcf5abf281058f0a6a97c5fd803c7d4d8d60c7d08c7c3fd0654631a36df9f1e806f" +
		"48c103d17580c1742e17c4f2ba2fb87d",
	)
	rootE = mustInt("" +
		"9a011cfb7ebb5e7ff32faa1aafbffcec7139691f8d3881ce14341ad276ed9eaf2a02a3e5dd4b29925750031766c0ed33" +
		"2fea542f748c946c67d8657e0f65dacd42b20764ede5f073c75e7fa24f27304cbf4b5850a090a1b4271bbf064f21590c" +
		"44fc01290ab7904c014944010e1eb7b8fac4a3b5d6a93a8fff42bb31a63053f1bcaa494253ace60e0fdf0e13e464f8d1" +
		"a686ec3ff226ed6624f02302097929ca877678c6b6fd3c9875941d5e95b92508f873f2b4de1113b8e0d2568a90ddec93" +
		"563ab933257d899504c0c17a3cd397d9d29a43360a8f2f7058b3806ec7a8bf8d61ef8e9b1d21bc6c97d95f815c0b9858" +
		"98634aef86a5e0275d689f63540b2a3",
	)
)

// DH domain parameters: a 2048-bit prime with a 256-bit prime-order subgroup, generated with crypto/dsa (L2048N256).
var (
	dhP = mustInt("" +
		"df98209b3bef9b79951a51bedfc44985af545252dc32494fb0b02d3827bbb00665f93618172ef7b3de4eaef29f74aa21" +
		"2677e4d34f12f0b870a1ca1b68162534f9e0c5b6beccb40861d80186187464683984625bf41f5c1341a56666f48e3b4f" +
		"128fb096adc05be1ae0b0db5be30869022acd3ddc318187d055d9330ef35d17a780034143e8930808152873e4882ddc0" +
		"6822a3adf0bc4bdd95d304afee51d9e0c3a1061f527b0984772450a35552a2c5df97c154481e7fd5842ea7283e5eeeda" +
		"fd26bb31f819e786f687a04b1b97f4a8ef861a07c25248cde6cf8735cbf0ff0111a498833fd9b13f1ba4e73934a0a16a" +
		"52ff716721cefe89a775e61534f2a605",
	)
	dhQ = mustInt("" +
		"ffd07bd86d560bb6f86532532928ecbb0151b6706886c1e5d833a0de97063b2f",
	)
	dhG = mustInt("" +
		"9c803e7d3ff74e4733667e5bd916529a30b6305ec97937371d9e7e66097597372620e69cccd8008a9da4a510e1f1953b" +
		"d4827baf4d881a735dbe70753f7fbcf3957038082016475d30105c630d057b48c4f83ee0b749984e3cf03272a0387199" +
		"7c94decae88d62297a17c9b5e88e5f7e6e2b506e9f33aa49c09fbf91dbdcb81c1c61213b0bfa6e1a1c7b5373a4521806" +
		"b3bc53a244d3180ff0c97339fa608c4a3a81af0abf7cd805336af1cb3be69b5986fd733067386c4476cc7c79bcf402d6" +
		"a2c7ee0da076bcb7a4d1e933ccadcbf9178b786c5dc112c25fe1dc183facce626898e4f795dfc95fdbec9bd45b4fe3c0" +
		"eb9e0bddbdd125e363943475494034dc",
	)
)

func mustInt(s string) *big.Int {
	v, ok := new(big.Int).SetString(s, 16)
	if !ok {
		panic("bad hex constant")
	}
	return v
}
