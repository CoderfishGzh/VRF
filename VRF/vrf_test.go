package vrf

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"testing"
	"github.com/stretchr/testify/assert"
)

func TestVry(t *testing.T) {

	// get key
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		fmt.Println("密钥对生成失败：", err)
		panic(err)
	}

	message := []byte("VRF") 

	proof, result, err := runVRF(privateKey, message)
	if err != nil {
		panic(err)
	}

	fmt.Println("proof: ", proof)
	fmt.Println("result: ", result)

	// 验证VRF结果
	isValid := verifyVRF(&privateKey.PublicKey, message, proof, result)
	fmt.Println("验证结果：", isValid)
	assert.True(t, isValid, "验证失败")	
	mappedResult := mapToRange(result, 0, 100)
	fmt.Println("映射后结果：", mappedResult)

	if isValid {
		if mappedResult > 50 {
			fmt.Println("yes")
		} else {
			fmt.Println("No")
		}
	} else {
		fmt.Println("verify vrf error")
	}
}
