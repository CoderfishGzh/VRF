package vrf

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"math/big"
)

// 运行VRF算法
func runVRF(privateKey *ecdsa.PrivateKey, message []byte) ([]byte, *big.Int, error) {
	// 使用SHA-256哈希函数计算消息摘要
	hash := sha256.Sum256(message)

	// 使用私钥对摘要进行签名
	r, s, err := ecdsa.Sign(rand.Reader, privateKey, hash[:])
	if err != nil {
		return nil, nil, err
	}

	// 将签名的r和s值拼接作为证明
	proof := append(r.Bytes(), s.Bytes()...)

	// 使用公钥和消息计算结果
	result := calculateResult(&privateKey.PublicKey, hash[:])

	return proof, result, nil
}

// 计算结果
func calculateResult(publicKey *ecdsa.PublicKey, message []byte) *big.Int {
	// 使用SHA-256哈希函数计算消息摘要
	hash := sha256.Sum256(message)

	// 将哈希结果转换为big.Int类型
	hashInt := new(big.Int).SetBytes(hash[:])

	// 使用公钥的x坐标和哈希结果进行乘法运算
	result := new(big.Int).Mul(publicKey.X, hashInt)

	return result
}

// 验证VRF结果
func verifyVRF(publicKey *ecdsa.PublicKey, message, proof []byte, result *big.Int) bool {
	// 使用SHA-256哈希函数计算消息摘要
	hash := sha256.Sum256(message)

	// 使用公钥验证签名
	r := new(big.Int).SetBytes(proof[:len(proof)/2])
	s := new(big.Int).SetBytes(proof[len(proof)/2:])
	return ecdsa.Verify(publicKey, hash[:], r, s)
}

// 比较结果并判断被选中
func compareResults(result, threshold *big.Int) bool {
	// 比较结果与阈值的大小
	return result.Cmp(threshold) < 0
}

// 将结果映射到指定范围
func mapToRange(result *big.Int, min, max int64) int64 {
	// 将结果限制在 0-100 范围内
	if result.Sign() < 0 {
		result.Neg(result)
	}
	result.Mod(result, big.NewInt(101))

	// 将结果转换为 int64 类型
	mappedResult := result.Int64() + min

	return mappedResult
}
